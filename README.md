# PyEVP

[![Documentation](https://app.readthedocs.org/projects/pyevp/badge/?version=latest)](https://docs.pyevp.dev/en/latest/)
[![CI](https://github.com/gaato/pyevp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gaato/pyevp/actions/workflows/ci.yml)
[![Spec drift](https://github.com/gaato/pyevp/actions/workflows/drift.yml/badge.svg)](https://github.com/gaato/pyevp/actions/workflows/drift.yml)
[![spec: draft-hardt-02](https://img.shields.io/badge/spec-draft--hardt--02-blue)](https://github.com/dickhardt/email-verification)
![status: alpha](https://img.shields.io/badge/status-alpha-orange)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/gaato/pyevp/blob/main/LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/gaato/pyevp)

[日本語](https://github.com/gaato/pyevp/blob/main/README.ja.md)

Python library for the **Email Verification Protocol** (EVP): verify tokens as a relying party,
or issue them for your own email domains. With EVP, the browser obtains a token from the user's
email provider proving they control an address, and your server verifies it, with no confirmation
email round-trip.

**Documentation: <https://docs.pyevp.dev/>**

> **Status: alpha.** The protocol ([draft-hardt-email-verification], [WICG Email Verification API])
> and browser support (Chrome origin trial) are still changing. This library isolates every
> moving part in a versioned `Profile` so it can follow along.

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification

## Install

```sh
pip install "pyevp[dns,httpx2]"   # core + the DNS and HTTP adapters
```

The core depends only on [joserfc] and idna. DNS and HTTP are pluggable; `[dns,httpx2]` installs
the default adapters used by `Verifier.default()`. `[all]` installs every optional dependency,
including the Django integration and the command line.

The HTTP adapters work with [httpx2] (pydantic's maintained fork of httpx) or httpx and prefer
httpx2 when both are installed, so `pip install "pyevp[dns,httpx]"` works too. A client from either
library can be passed explicitly, e.g. `HttpxFetcher(httpx.Client(...))`.

[httpx2]: https://github.com/pydantic/httpx2

[joserfc]: https://jose.authlib.org/

## How it works

1. Render a form with a fresh nonce stored in the user's session:

   ```html
   <input type="email" name="email" autocomplete="email">
   <input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
   ```

2. When the user picks an address, the browser fills `evt` with `<EVT>~<KB-JWT>`.
3. On submit, verify it:

   ```python
   from pyevp import Verifier, EVPError, generate_nonce

   verifier = Verifier.default(audience="https://example.com")  # your origin

   try:
       result = verifier.verify(form["evt"], nonce=session.pop("evp_nonce"), email=form["email"])
   except EVPError as exc:
       ...  # exc.code is a stable ErrorCode, e.g. "nonce_mismatch"; fall back to email confirmation
   else:
       result.email, result.issuer  # verified
   ```

   `AsyncVerifier` has the same API with `await verifier.verify(...)`.

Verification checks the key-binding JWT (audience, nonce, freshness, `sd_hash`, holder signature)
before doing any I/O. It then discovers the issuer from DNS (`_email-verification.<domain>`
TXT `iss=…`), fetches its metadata and JWKS (cached), and verifies the issuer's signature. Only
hosts derived from DNS are ever contacted, never hosts named in the token, and only when they
resolve to public addresses.

Every rejected token raises an `EVPError` with a stable `ErrorCode`. The safe default is to fall back to your existing
verification flow; the [error table](https://docs.pyevp.dev/en/latest/quickstart.html#handle-failures) tells which codes
the user can retry and which point at your configuration.

## Command line

`pyevp[cli]` installs a `pyevp` command for relying-party developers and operators, and for
issuer operators checking their own setup. It runs without installing anything into your project:

```sh
uvx --from "pyevp[cli]" pyevp discover gmail.com           # DNS record, metadata, keys vs. profile
pbpaste | uvx --from "pyevp[cli]" pyevp inspect            # decode a token offline (no signature checks)
uvx --from "pyevp[cli]" pyevp verify "$TOKEN" --audience https://example.com --nonce "$NONCE"
```

See the [CLI guide](https://docs.pyevp.dev/en/latest/guides/cli.html) for every command and option.

## More

- [Frameworks](https://docs.pyevp.dev/en/latest/guides/frameworks.html): FastAPI, Flask, fastapi-users, AuthX and Django
- [Testing your application](https://docs.pyevp.dev/en/latest/guides/testing.html): `FakeIssuer` and `FakeBrowser`, no network needed
- [Replay protection](https://docs.pyevp.dev/en/latest/guides/replay.html), [logging and metrics](https://docs.pyevp.dev/en/latest/guides/observability.html)
- [DNS, HTTP and caching](https://docs.pyevp.dev/en/latest/guides/transport.html): DNS over HTTPS, a standard-library-only setup, private networks
- [Profiles](https://docs.pyevp.dev/en/latest/concepts.html#profiles): how PyEVP follows a protocol that is still changing
- [Running an issuer](https://docs.pyevp.dev/en/latest/guides/issuer-operations.html) for your own mail domains
- [Compatibility policy](https://docs.pyevp.dev/en/latest/compatibility.html)

## Examples

Each example is a standalone project with its own tests:

- [`examples/fastapi`](https://github.com/gaato/pyevp/blob/main/examples/fastapi/app.py): FastAPI with session nonces
- [`examples/flask`](https://github.com/gaato/pyevp/blob/main/examples/flask/app.py): the same flow with the synchronous `Verifier`
- [`examples/fastapi_spa`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_spa/app.py): a JSON API for a single-page app, without server sessions, with password recovery
- [`examples/fastapi_users`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_users/app.py): fastapi-users registration that falls back to the usual verification email
- [`examples/authx`](https://github.com/gaato/pyevp/blob/main/examples/authx/app.py): passwordless login with AuthX
- [`examples/django`](https://github.com/gaato/pyevp/blob/main/examples/django/views.py): plain Django with the template tag and `verify_request`
- [`examples/django_allauth`](https://github.com/gaato/pyevp/blob/main/examples/django_allauth/evp_allauth.py): a django-allauth adapter
- [`examples/issuer_fastapi`](https://github.com/gaato/pyevp/blob/main/examples/issuer_fastapi/app.py): an issuer for your own domains
- [`examples/issuer_django`](https://github.com/gaato/pyevp/blob/main/examples/issuer_django/urls.py): the same issuer on Django, with Django's own users

## Contributing

See [CONTRIBUTING.md](https://github.com/gaato/pyevp/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/gaato/pyevp/blob/main/LICENSE)
