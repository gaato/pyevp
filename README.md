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

**Documentation: <https://docs.pyevp.dev/>** · **Live demo: <https://pyevp.dev/demo>**

> **Status: alpha.** The protocol ([draft-hardt-email-verification], [WICG Email Verification API])
> is still changing. PyEVP keeps every moving part in a versioned `Profile` so it can follow along.

- **Browsers:** Chrome, with `chrome://flags/#email-verification-protocol` enabled or on a site
  registered for the origin trial. Tested with Chrome 154. Other browsers send no token.
- **Email providers:** Gmail issues tokens today. Your own domains can too, with `pyevp.issuer`.
- **Python:** 3.11 or newer.

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification

## Install

```sh
pip install "pyevp[dns,httpx2]"   # core + the DNS and HTTP adapters
```

The core depends only on [joserfc] and idna. `[dns,httpx2]` adds the adapters
`Verifier.default()` uses; httpx works too (see [DNS, HTTP and caching]). `[all]` adds the Django
integration and the command line.

[joserfc]: https://jose.authlib.org/
[DNS, HTTP and caching]: https://docs.pyevp.dev/en/latest/guides/transport.html

## How it works

1. Render a form with a nonce kept in the user's session:

   ```python
   from pyevp import SessionNonces, token_input

   nonce = SessionNonces(session).issue()  # Flask, Starlette and Django sessions all work
   ```

   ```html
   <input type="email" name="email" autocomplete="email">
   <input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
   ```

   (`token_input(nonce)` renders the hidden input.)

2. When the user picks an address, the browser fills `evt` with `<EVT>~<KB-JWT>`.
3. On submit, verify it:

   ```python
   from pyevp import EVPError, SessionNonces, Verifier

   verifier = Verifier.default(audience="https://example.com")  # your origin

   try:
       result = verifier.verify_submission(
           form.get("evt"), nonces=SessionNonces(session), email=form["email"]
       )
   except EVPError as exc:
       ...  # exc.code says why, e.g. "nonce_mismatch"; fall back to email confirmation
   else:
       if result is None:
           ...  # no token: fall back to email confirmation
       else:
           result.email, result.issuer  # verified
   ```

   `AsyncVerifier` has the same API with `await`.

Everything that can be checked offline is checked first, and only hosts found through DNS are
ever contacted, never hosts named in the token. Every rejection raises an `EVPError` with an
[error code](https://docs.pyevp.dev/en/latest/quickstart.html#handle-failures).

## More

- [Quickstart](https://docs.pyevp.dev/en/latest/quickstart.html) and [concepts](https://docs.pyevp.dev/en/latest/concepts.html)
- [Frameworks](https://docs.pyevp.dev/en/latest/guides/frameworks.html): FastAPI, Flask, fastapi-users, AuthX and Django
- [Testing your application](https://docs.pyevp.dev/en/latest/guides/testing.html) without network access
- [Replay protection](https://docs.pyevp.dev/en/latest/guides/replay.html), [logging and metrics](https://docs.pyevp.dev/en/latest/guides/observability.html)
- [Command line](https://docs.pyevp.dev/en/latest/guides/cli.html): `uvx --from "pyevp[cli]" pyevp discover gmail.com` checks a domain's issuer
- [Running an issuer](https://docs.pyevp.dev/en/latest/guides/issuer-operations.html) for your own mail domains
- [Compatibility policy](https://docs.pyevp.dev/en/latest/compatibility.html)

## Examples

Each example is a standalone project with its own tests:

- [`examples/fastapi`](https://github.com/gaato/pyevp/blob/main/examples/fastapi/app.py): FastAPI with session nonces
- [`examples/flask`](https://github.com/gaato/pyevp/blob/main/examples/flask/app.py): the same flow with the synchronous `Verifier`
- [`examples/fastapi_spa`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_spa/app.py): a JSON API for a single-page app, with password recovery
- [`examples/fastapi_users`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_users/app.py): fastapi-users registration
- [`examples/authx`](https://github.com/gaato/pyevp/blob/main/examples/authx/app.py): passwordless login with AuthX
- [`examples/django`](https://github.com/gaato/pyevp/blob/main/examples/django/views.py): Django with the template tag
- [`examples/django_allauth`](https://github.com/gaato/pyevp/blob/main/examples/django_allauth/evp_allauth.py): a django-allauth adapter
- [`examples/issuer_fastapi`](https://github.com/gaato/pyevp/blob/main/examples/issuer_fastapi/app.py), [`examples/issuer_django`](https://github.com/gaato/pyevp/blob/main/examples/issuer_django/urls.py): an issuer for your own domains

## Contributing

See [CONTRIBUTING.md](https://github.com/gaato/pyevp/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/gaato/pyevp/blob/main/LICENSE)
