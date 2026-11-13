"""End-to-end EVP check against the public https://mail.pyevp.dev demo provider.

Checks the provider before launching Chrome, then starts the example relying party
(``examples/fastapi``) from this checkout on localhost and drives a fresh Chrome
profile over DevTools. The provider runs the deployed :latest image, independently
of the RP library under test. Provider unavailability exits with code 2; interop
failures exit with code 1.

Run from the repository root::

    uv run --locked --all-packages --group interop python interop/chrome_evp.py

Environment:

``CHROME``
    Chrome binary (default ``google-chrome``).
``INTEROP_OUT``
    Directory for logs and screenshots (default: a temporary directory).
``INTEROP_HEADFUL``
    Set to show the browser window.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import websockets
from dns.exception import DNSException

from pyevp.adapters.dnspython import DnsPythonResolver
from pyevp.discovery import parse_txt_records
from pyevp.errors import DiscoveryError

ROOT = Path(__file__).resolve().parent.parent
ISSUER = "https://mail.pyevp.dev"
WEB_IDENTITY = "https://pyevp.dev/.well-known/web-identity"
TXT_NAME = "_email-verification.pyevp.dev"
RP_PORT = 8001
RP = f"http://localhost:{RP_PORT}"
EMAIL = "demo@pyevp.dev"
EXPECTED_RESULT = {"verified": True, "issuer": ISSUER}
PROVIDER_UNAVAILABLE_EXIT = 2
CDP_PORT = 9333
ATTEMPTS = 3

# issuer_site is the issuer origin (https://mail.pyevp.dev), not its site: the
# first run against the public provider passed on stable and beta (2026-10-03).
CHROME_ISSUER_SITE = ISSUER

# Chrome asks once per address before its first issuance ("verify this email
# automatically?"). The prompt is browser UI that DevTools cannot click, so the
# profile starts with the answer Chrome stores after the user accepts.
PREFERENCES = {
    "autofill": {
        "email_verification_state": {
            EMAIL: {
                "allowed": True,
                "issuer_site": CHROME_ISSUER_SITE,
                "timestamp": "13435404633497937",
            }
        }
    },
    # Keep the "save password?" bubble out of the way after the issuer login.
    "credentials_enable_service": False,
    "profile": {"password_manager_enabled": False},
}


class InteropError(Exception):
    pass


class ProviderUnavailable(Exception):
    """The public provider or its discovery setup is unavailable."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    content_type: str
    body: bytes


@dataclass(frozen=True)
class SessionState:
    email: str | None
    issued: int
    build_sha: str


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # The standard library defines this callback's positional signature.
    def redirect_request(self, req, fp, code, msg, headers, newurl) -> None:  # noqa: PLR0917
        # In particular, never forward the provider's session cookie elsewhere.
        return None


def fetch_response(url: str, *, cookie: str = "") -> HttpResponse:
    headers = {"User-Agent": "pyevp-interop", "Cache-Control": "no-cache"}
    if cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=10) as response:
        return HttpResponse(
            response.status, response.headers.get("Content-Type", ""), response.read()
        )


def parse_json(response: HttpResponse, description: str) -> Any:
    if response.status != 200:
        raise ProviderUnavailable(f"{description}: HTTP {response.status}")
    if response.content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ProviderUnavailable(f"{description}: expected application/json")
    try:
        return json.loads(response.body)
    except (ValueError, UnicodeError) as exc:
        raise ProviderUnavailable(f"{description}: invalid JSON") from exc


def validate_web_identity(document: object) -> None:
    endpoint = document.get("accounts_endpoint") if isinstance(document, dict) else None
    try:
        parts = urlsplit(endpoint) if isinstance(endpoint, str) else None
        valid = (
            parts is not None
            and parts.scheme == "https"
            and parts.hostname == "mail.pyevp.dev"
            and parts.port in (None, 443)
            and parts.username is None
            and parts.password is None
        )
    except ValueError:
        valid = False
    if not valid:
        raise ProviderUnavailable(
            "web-identity: accounts_endpoint must be on https://mail.pyevp.dev"
        )


def parse_me(document: object) -> SessionState:
    if not isinstance(document, dict):
        raise ProviderUnavailable("/me: expected a JSON object")
    email, issued, build_sha = (document.get(key) for key in ("email", "issued", "build_sha"))
    if "email" not in document or (email is not None and not isinstance(email, str)):
        raise ProviderUnavailable("/me: invalid email")
    if not isinstance(issued, int) or isinstance(issued, bool) or issued < 0:
        raise ProviderUnavailable("/me: issued must be a non-negative integer")
    if not isinstance(build_sha, str) or not build_sha:
        raise ProviderUnavailable("/me: invalid build_sha")
    return SessionState(email, issued, build_sha)


def preflight(
    get: Callable[[str], HttpResponse] = fetch_response,
    resolve_txt: Callable[[str], Sequence[str]] | None = None,
) -> None:
    """Check public infrastructure without starting the RP or Chrome."""
    try:
        health = get(f"{ISSUER}/healthz")
        if health.status != 200:
            raise ProviderUnavailable(f"healthz: HTTP {health.status}")
        validate_web_identity(parse_json(get(WEB_IDENTITY), "web-identity"))
        resolve_txt = resolve_txt or DnsPythonResolver().resolve_txt
        issuer = parse_txt_records(resolve_txt(TXT_NAME))
        if issuer != ISSUER:
            raise ProviderUnavailable(f"{TXT_NAME}: discovered {issuer}, expected {ISSUER}")
    except (OSError, ValueError, http.client.HTTPException, DNSException, DiscoveryError) as exc:
        raise ProviderUnavailable(f"preflight: {exc}") from exc


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def fetch_json(url: str) -> Any:
    # Cloudflare's bot protection answers urllib's default User-Agent with 403.
    request = urllib.request.Request(url, headers={"User-Agent": "pyevp-interop"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def wait_for(description: str, check, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        with contextlib.suppress(OSError, ValueError):
            if check():
                return
        if time.monotonic() > deadline:
            raise InteropError(f"timed out waiting for {description}")
        time.sleep(1)


@contextlib.contextmanager
def process(name: str, args: list[str], out: Path, **kwargs: Any) -> Generator[None]:
    with (out / f"{name}.log").open("w") as logfile:
        proc = subprocess.Popen(args, stdout=logfile, stderr=subprocess.STDOUT, **kwargs)
        try:
            yield
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()


class DevTools:
    """Just enough of the Chrome DevTools protocol for one page."""

    def __init__(self, ws: websockets.ClientConnection) -> None:
        self._ws = ws
        self._next_id = 0

    async def send(self, method: str, **params: Any) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        await self._ws.send(json.dumps({"id": request_id, "method": method, "params": params}))
        while True:
            message = json.loads(await asyncio.wait_for(self._ws.recv(), 30))
            if message.get("id") != request_id:
                continue  # an event; we poll page state instead
            if "error" in message:
                raise InteropError(f"{method}: {message['error']}")
            return message.get("result", {})

    async def evaluate(self, expression: str) -> Any:
        result = await self.send(
            "Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True
        )
        return result.get("result", {}).get("value")

    async def navigate(self, url: str) -> None:
        await self.send("Page.navigate", url=url)
        await self.wait_loaded()

    async def wait_loaded(self) -> None:
        for _ in range(150):
            await asyncio.sleep(0.2)
            if await self.evaluate("document.readyState") == "complete":
                return
        raise InteropError("page did not finish loading")

    async def click(self, selector: str) -> None:
        """A trusted click: Chrome inserts the token only on a real form submission."""
        box = await self.evaluate(
            f"JSON.stringify(document.querySelector({json.dumps(selector)})"
            ".getBoundingClientRect())"
        )
        rect = json.loads(box)
        x, y = rect["x"] + rect["width"] / 2, rect["y"] + rect["height"] / 2
        for kind in ("mousePressed", "mouseReleased"):
            await self.send(
                "Input.dispatchMouseEvent", type=kind, x=x, y=y, button="left", clickCount=1
            )

    async def key(self, key: str, code: int) -> None:
        for kind in ("rawKeyDown", "keyUp"):
            await self.send(
                "Input.dispatchKeyEvent", type=kind, key=key, code=key, windowsVirtualKeyCode=code
            )

    async def screenshot(self, path: Path) -> None:
        result = await self.send("Page.captureScreenshot", format="png")
        path.write_bytes(base64.b64decode(result["data"]))


class ProviderSession:
    """Read /me with Chrome's current cookies without moving the RP page.

    Cookies are retrieved again on every poll: issuance can update a signed
    session cookie. urllib never writes cookies back to Chrome or follows redirects.
    """

    def __init__(self, tab: DevTools) -> None:
        self._tab = tab
        self._build_sha: str | None = None

    async def read(self) -> SessionState:
        url = f"{ISSUER}/me"
        result = await self._tab.send("Network.getCookies", urls=[url])
        cookie = "; ".join(f"{c['name']}={c['value']}" for c in result["cookies"])
        try:
            response = await asyncio.to_thread(fetch_response, url, cookie=cookie)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ProviderUnavailable(f"/me: {exc}") from exc
        state = parse_me(parse_json(response, "/me"))
        if state.build_sha != self._build_sha:
            log(f"provider build_sha={state.build_sha}")
            self._build_sha = state.build_sha
        if state.email != EMAIL:
            raise InteropError(f"provider session is not logged in as {EMAIL}")
        return state

    async def wait_for_token(self, before: SessionState, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = await self.read()
            if state.issued > before.issued:
                log(f"issuer issued a token ({before.issued} -> {state.issued})")
                # Chrome still binds the token to its key; that is local and quick.
                await asyncio.sleep(1)
                return
            if state.issued < before.issued:
                raise InteropError("provider session's issued count decreased")
            await asyncio.sleep(0.5)
        raise InteropError("Chrome did not obtain a token: /me issued count did not increase")


async def drive(out: Path) -> dict[str, Any]:
    targets = fetch_json(f"http://127.0.0.1:{CDP_PORT}/json")
    page = next(t for t in targets if t["type"] == "page")
    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        tab = DevTools(ws)
        await tab.send("Page.enable")
        await tab.send("Network.enable")
        session = ProviderSession(tab)
        try:
            log(f"logging in to the issuer as {EMAIL}")
            await tab.navigate(f"{ISSUER}/login")
            submitted = await tab.evaluate(
                "(() => { const f = document.querySelector('form[action=\"/login\"]');"
                " if (!f || f.method.toLowerCase() !== 'post') return false;"
                " f.submit(); return true; })()"
            )
            if not submitted:
                raise InteropError("provider login page has no POST /login form")
            await asyncio.sleep(1)
            await tab.wait_loaded()
            await session.read()  # Check the login and report the deployed build.

            for attempt in range(1, ATTEMPTS):
                result = await submit_form(tab, session)
                if result.get("verified"):
                    return result
                # The token arrived too late for this submission; try a fresh form.
                log(f"attempt {attempt} was not verified: {result}")
            return await submit_form(tab, session)
        finally:
            with contextlib.suppress(Exception):
                await tab.screenshot(out / "final.png")


async def submit_form(tab: DevTools, session: ProviderSession) -> dict[str, Any]:
    log("filling in the relying party's form")
    await tab.navigate(RP)
    before = await session.read()
    await tab.evaluate("document.querySelector('input[name=email]').focus()")
    await tab.send("Input.insertText", text=EMAIL)
    await tab.key("Tab", 9)  # Chrome starts the check when the field loses focus
    await session.wait_for_token(before, timeout=60)

    log("submitting")
    await tab.click("button")
    await asyncio.sleep(1)
    await tab.wait_loaded()
    text = await tab.evaluate("document.body.innerText")
    try:
        result = json.loads(text)
    except ValueError:
        raise InteropError(f"unexpected RP response: {text!r}") from None
    if not isinstance(result, dict):
        raise InteropError(f"unexpected RP response: {text!r}")
    return result


def run(out: Path) -> None:
    log("checking public demo provider availability")
    preflight()
    log("provider preflight passed")
    chrome = os.environ.get("CHROME", "google-chrome")

    tmp = Path(tempfile.mkdtemp(prefix="pyevp-interop-"))
    try:
        profile = tmp / "profile"
        (profile / "Default").mkdir(parents=True)
        (profile / "Default" / "Preferences").write_text(json.dumps(PREFERENCES))

        rp_env = {**os.environ, "EVP_ORIGIN": RP, "SESSION_SECRET": secrets.token_hex(32)}
        uvicorn_args = [sys.executable, "-m", "uvicorn", "app:app", "--port"]
        chrome_args = [
            chrome,
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={CDP_PORT}",
            "--enable-features=EmailVerificationProtocol",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1280,900",
        ]
        if not os.environ.get("INTEROP_HEADFUL"):
            chrome_args.append("--headless=new")
        chrome_args.append("about:blank")

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                process(
                    "rp",
                    [*uvicorn_args, str(RP_PORT)],
                    out,
                    cwd=ROOT / "examples" / "fastapi",
                    env=rp_env,
                )
            )
            wait_for("relying party", lambda: fetch_response(RP).status == 200)
            stack.enter_context(process("chrome", chrome_args, out))
            wait_for("Chrome", lambda: fetch_json(f"http://127.0.0.1:{CDP_PORT}/json/version"))
            version = fetch_json(f"http://127.0.0.1:{CDP_PORT}/json/version")["Browser"]
            log(f"driving {version}")

            result = asyncio.run(drive(out))
            log(f"relying party answered {result}")
            actual = {key: result.get(key) for key in EXPECTED_RESULT}
            if actual != EXPECTED_RESULT or result.get("email") != EMAIL:
                raise InteropError(f"token was not verified: {result}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    out = Path(os.environ.get("INTEROP_OUT") or tempfile.mkdtemp(prefix="pyevp-interop-out-"))
    out.mkdir(parents=True, exist_ok=True)
    try:
        run(out)
    except ProviderUnavailable as exc:
        log(f"PROVIDER UNAVAILABLE: {exc} (logs in {out})")
        return PROVIDER_UNAVAILABLE_EXIT
    except (InteropError, urllib.error.URLError) as exc:
        log(f"INTEROP FAILED: {exc} (logs in {out})")
        return 1
    log("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
