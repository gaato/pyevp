"""Command-line tools for relying parties and issuer operators.

- ``pyevp discover``: check a domain's issuer as a relying party would see it.
- ``pyevp inspect``: decode a presentation token offline (signatures not checked).
- ``pyevp verify``: run the full verification of a token.
- ``pyevp issuer keygen`` / ``pyevp issuer documents``: set up an issuer.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from joserfc import jwk
from rich.console import Console
from rich.table import Table

from pyevp.diagnostics import IssuerReport, discover
from pyevp.errors import EVPError
from pyevp.issuer import SIGNING_ALGORITHMS, Issuer, SigningKey
from pyevp.ports import JsonFetcher, TxtResolver
from pyevp.profile import DEFAULT_PROFILE, PROFILES, Profile
from pyevp.token import ParsedToken, compute_sd_hash, parse_token
from pyevp.verifier import Verifier

__all__ = ["app", "make_app"]

FAILED = 1
MISSING_EXTRA = 3

ResolverFactory = Callable[[str | None], TxtResolver]
"""Builds a resolver; the argument is a DoH endpoint, or ``None`` for plain DNS."""
FetcherFactory = Callable[[], JsonFetcher]


def _default_resolver(doh_endpoint: str | None) -> TxtResolver:
    if doh_endpoint is not None:
        from pyevp.adapters.doh import DohResolver  # noqa: PLC0415

        return DohResolver(doh_endpoint)
    from pyevp.adapters.dnspython import DnsPythonResolver  # noqa: PLC0415

    return DnsPythonResolver()


def _default_fetcher() -> JsonFetcher:
    from pyevp.adapters.httpx import HttpxFetcher  # noqa: PLC0415

    return HttpxFetcher()


def _profile(name: str) -> Profile:
    try:
        return Profile.named(name)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


def _json(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2, default=str, ensure_ascii=False))


def _age(timestamp: Any, now: datetime) -> str:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int | float):
        return "-"
    try:
        seconds = int((now - datetime.fromtimestamp(timestamp, UTC)).total_seconds())
    except (OverflowError, OSError, ValueError):
        return "-"
    return f"{seconds}s ago" if seconds >= 0 else f"in {-seconds}s"


ProfileOption = Annotated[
    str, typer.Option("--profile", "-p", help=f"Profile preset: {', '.join(PROFILES)}.")
]
DohOption = Annotated[
    bool, typer.Option("--doh", help="Resolve DNS over HTTPS instead of the system resolver.")
]
DohEndpointOption = Annotated[str, typer.Option("--doh-endpoint", help="DoH JSON API endpoint.")]
JsonOption = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]


def make_app(
    *,
    resolver_factory: ResolverFactory = _default_resolver,
    fetcher_factory: FetcherFactory = _default_fetcher,
    console: Console | None = None,
) -> typer.Typer:
    """Build the CLI; tests inject in-memory ports through the factories."""
    app = typer.Typer(
        help="Email Verification Protocol tools.",
        no_args_is_help=True,
        add_completion=False,
        pretty_exceptions_enable=False,
    )
    out = console or Console()

    def ports(doh: bool, doh_endpoint: str) -> tuple[TxtResolver, JsonFetcher]:
        try:
            return resolver_factory(doh_endpoint if doh else None), fetcher_factory()
        except ImportError as exc:
            typer.echo(f'Missing dependency {exc.name!r}: pip install "pyevp[cli]"', err=True)
            raise typer.Exit(MISSING_EXTRA) from None

    @app.command("discover")
    def discover_cmd(
        target: Annotated[str, typer.Argument(help="Email address or domain.")],
        profile: ProfileOption = DEFAULT_PROFILE.name,
        doh: DohOption = False,
        doh_endpoint: DohEndpointOption = "https://dns.google/resolve",
        as_json: JsonOption = False,
    ) -> None:
        """Check a domain's issuer: DNS record, metadata and keys."""
        resolver, fetcher = ports(doh, doh_endpoint)
        try:
            report = discover(target, resolver=resolver, fetcher=fetcher, profile=_profile(profile))
        except EVPError as exc:
            _fail(out, as_json, exc)
        finally:
            _close(resolver, fetcher)
        if as_json:
            _json(asdict(report) | {"ok": report.ok})
        else:
            _print_report(out, report)
        if not report.ok:
            raise typer.Exit(FAILED)

    @app.command("inspect")
    def inspect_cmd(
        token: Annotated[str, typer.Argument(help="Presentation token, or - for stdin.")] = "-",
        as_json: JsonOption = False,
    ) -> None:
        """Decode a token offline.  Signatures are NOT verified."""
        raw = sys.stdin.read() if token == "-" else token
        try:
            parsed = parse_token(raw, allow_disclosures=True)
        except EVPError as exc:
            _fail(out, as_json, exc)
        data = _inspection(parsed, datetime.now(UTC))
        if as_json:
            _json(data)
        else:
            _print_inspection(out, data)

    @app.command("verify")
    def verify_cmd(
        token: Annotated[str, typer.Argument(help="Presentation token, or - for stdin.")],
        audience: Annotated[str, typer.Option(help="Your origin, e.g. https://example.com.")],
        nonce: Annotated[str, typer.Option(help="The nonce that was put on the form.")],
        email: Annotated[str | None, typer.Option(help="Submitted address to compare.")] = None,
        profile: ProfileOption = DEFAULT_PROFILE.name,
        doh: DohOption = False,
        doh_endpoint: DohEndpointOption = "https://dns.google/resolve",
        as_json: JsonOption = False,
    ) -> None:
        """Fully verify a token, as a relying party would."""
        raw = sys.stdin.read() if token == "-" else token
        resolver, fetcher = ports(doh, doh_endpoint)
        try:
            verifier = Verifier(
                audience=audience, resolver=resolver, fetcher=fetcher, profile=_profile(profile)
            )
            result = verifier.verify(raw.strip(), nonce=nonce, email=email)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from None
        except EVPError as exc:
            _fail(out, as_json, exc)
        finally:
            _close(resolver, fetcher)
        if as_json:
            _json({"ok": True} | asdict(result))
        else:
            out.print(f"[green]verified[/green] {result.email} (issuer {result.issuer})")

    app.add_typer(_issuer_app(), name="issuer")
    return app


def _issuer_app() -> typer.Typer:
    app = typer.Typer(help="Set up an issuer for your own email domains.", no_args_is_help=True)

    @app.command("keygen")
    def keygen_cmd(
        kid: Annotated[str, typer.Option(help="Key id, e.g. the date: 2026-10.")],
        out_path: Annotated[
            Path, typer.Option("--out", help="Private JWK file to create (mode 0600).")
        ],
        alg: Annotated[str, typer.Option(help="Ed25519 or ES256.")] = "Ed25519",
    ) -> None:
        """Generate a signing key.  Prints the public JWK; the private one goes to --out."""
        if alg not in SIGNING_ALGORITHMS:
            choices = ", ".join(sorted(SIGNING_ALGORITHMS))
            raise typer.BadParameter(f"--alg must be one of {choices}")
        try:
            key = SigningKey.generate(alg, kid=kid)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from None
        try:
            fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise typer.BadParameter(f"{out_path} exists; refusing to overwrite a key") from None
        with os.fdopen(fd, "w") as file:
            json.dump(key.private_jwk(), file, indent=2)
            file.write("\n")
        _json(dict(key.public_jwk))

    @app.command("documents")
    def documents_cmd(
        issuer: Annotated[str, typer.Option(help="Issuer identifier, https://host.")],
        issuance_endpoint: Annotated[str, typer.Option(help="URL browsers POST requests to.")],
        jwks_uri: Annotated[str, typer.Option(help="URL the JWKS is served at.")],
        key: Annotated[Path, typer.Option(help="Private JWK file of the active key.")],
        domain: Annotated[list[str], typer.Option(help="Email domain served (repeatable).")],
        publish: Annotated[
            list[Path] | None,
            typer.Option(help="Extra JWK file to publish: next or retired key (repeatable)."),
        ] = None,
    ) -> None:
        """Print the metadata document, JWKS and DNS records to publish, as JSON."""
        try:
            signer = SigningKey.from_jwk(_read_json(key))
            extra = [_public_part(_read_json(p)) for p in publish or ()]
            built = Issuer(
                issuer=issuer,
                issuance_endpoint=issuance_endpoint,
                jwks_uri=jwks_uri,
                signer=signer,
                email_domains=domain,
                published_keys=extra,
            )
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from None
        _json(
            {
                "metadata_url": f"{built.issuer}/.well-known/email-verification",
                "metadata": built.metadata_document(),
                "jwks_uri": built.jwks_uri,
                "jwks": built.jwks_document(),
                "dns_txt": built.dns_txt_records(),
            }
        )

    return app


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    return value


def _public_part(jwk_: dict[str, Any]) -> dict[str, Any]:
    if "d" in jwk_:
        return dict(SigningKey.from_jwk(jwk_).public_jwk)
    return jwk_


def _close(*resources: object) -> None:
    for resource in resources:
        close = getattr(resource, "close", None)
        if callable(close):
            close()


def _fail(out: Console, as_json: bool, exc: EVPError) -> Any:
    if as_json:
        _json({"ok": False, "code": exc.code, "message": exc.args[0]})
    else:
        out.print(f"[red]{exc.code}[/red] {exc.args[0]}")
    raise typer.Exit(FAILED)


def _inspection(parsed: ParsedToken, now: datetime) -> dict[str, Any]:
    cnf = parsed.evt.claims.get("cnf")
    holder = cnf.get("jwk") if isinstance(cnf, dict) else None
    thumbprint = None
    if isinstance(holder, dict):
        try:
            thumbprint = jwk.thumbprint(holder)
        except Exception:
            thumbprint = None
    return {
        "signatures_verified": False,
        "evt": {"header": dict(parsed.evt.header), "claims": dict(parsed.evt.claims)},
        "disclosures": list(parsed.disclosures),
        "kb": {"header": dict(parsed.kb.header), "claims": dict(parsed.kb.claims)},
        "checks": {
            "evt_issued": _age(parsed.evt.claims.get("iat"), now),
            "kb_issued": _age(parsed.kb.claims.get("iat"), now),
            "sd_hash_matches": parsed.kb.claims.get("sd_hash")
            == compute_sd_hash(parsed.sd_hash_input),
            "holder_key_thumbprint": thumbprint,
        },
    }


def _table(title: str, columns: int) -> Table:
    table = Table(title=title, show_header=False, title_justify="left")
    for i in range(columns):
        table.add_column(style="bold" if i < columns - 1 else None, overflow="fold")
    return table


def _print_report(out: Console, report: IssuerReport) -> None:
    table = _table(f"Issuer for {report.domain}", 2)
    table.add_row("profile", report.profile)
    table.add_row("DNS name", report.dns_name)
    table.add_row("TXT records", "\n".join(report.records) or "[dim](none)[/dim]")
    table.add_row("issuer", report.issuer or "-")
    if report.metadata is not None:
        table.add_row("jwks_uri", report.metadata.jwks_uri)
        algs = report.metadata.signing_alg_values_supported
        table.add_row(
            "algorithms", "(not advertised)" if algs is None else ", ".join(algs) or "(none)"
        )
    for key in report.keys:
        table.add_row("key", f"{key.kty}/{key.crv} alg={key.alg} kid={key.kid!r}")
    out.print(table)
    for problem in report.problems:
        out.print(f"[red]✗[/red] {problem}")
    if report.ok:
        out.print("[green]✓ usable with this profile[/green]")


def _print_inspection(out: Console, data: dict[str, Any]) -> None:
    out.print("[yellow]Signatures are NOT verified; use `pyevp verify` for that.[/yellow]")
    for part in ("evt", "kb"):
        table = _table(part.upper(), 3)
        for section in ("header", "claims"):
            for name, value in data[part][section].items():
                table.add_row(section, name, json.dumps(value, ensure_ascii=False))
        out.print(table)
    checks = data["checks"]
    table = _table("checks", 2)
    for name, value in checks.items():
        table.add_row(name, str(value))
    out.print(table)


app = make_app()
