"""Minimal Flask relying party.

Run from this directory::

    uv run flask run --port 8000

then open http://localhost:8000 in a browser that supports the Email
Verification Protocol.  Tests pass a verifier wired to fakes to
``create_app`` (see ``tests/test_app.py``).
"""

from __future__ import annotations

import os

from flask import Flask, current_app, request, session

from pyevp import EVPError, InMemoryReplayGuard, SessionNonces, Verifier, token_input


def create_app(verifier: Verifier | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-only")
    origin = os.environ.get("EVP_ORIGIN", "http://localhost:8000")
    # Flask's default session is a signed cookie, so taking the nonce out of it does
    # not stop an attacker from resending a captured token with the old cookie.  The
    # replay guard does.  Use a shared store (e.g. Redis) when running more than
    # one worker process.
    app.extensions["evp_verifier"] = verifier or Verifier.default(
        audience=origin, replay_guard=InMemoryReplayGuard()
    )

    @app.get("/")
    def form() -> str:
        nonce = SessionNonces(session).issue()
        return f"""<!doctype html>
<form method="post" action="/signup">
  <input type="email" name="email" autocomplete="email" required>
  {token_input(nonce)}
  <button>Sign up</button>
</form>"""

    @app.post("/signup")
    def signup() -> tuple[dict[str, object], int] | dict[str, object]:
        # landing:start
        verifier: Verifier = current_app.extensions["evp_verifier"]
        email = request.form["email"]
        try:
            # Takes the token's nonce from the session, whether or not it verifies.
            result = verifier.verify_submission(
                request.form.get("evt"), nonces=SessionNonces(session), email=email
            )
        except EVPError as exc:
            return {"error": {"code": exc.code}}, 400
        if result is None:
            # No token: fall back to sending a confirmation email, as before EVP.
            return {"email": email, "verified": False}
        return {"email": result.email, "verified": True, "issuer": result.issuer}
        # landing:end

    return app
