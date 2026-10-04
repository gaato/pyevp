# PyEVP

Python library for the **Email Verification Protocol** (EVP): verify tokens as a relying party, or
issue them for your own email domains.

With EVP, the browser obtains a token from the user's email provider proving that the user
controls an address, and puts it in your sign-up or sign-in form. This library verifies that
token on your server, so no confirmation email round-trip is needed.

```{warning}
**Alpha.** The protocol ([draft-hardt-email-verification], [WICG Email Verification API]) and
browser support (Chrome origin trial) are still changing. Every moving part is isolated in a
versioned {doc}`profile <concepts>`, so the library can follow along without silent behaviour
changes.
```

- **Typed:** frozen dataclasses, protocols and stable error codes.
- **Sync and async from one core:** the verification logic does no I/O itself; thin drivers
  serve Django and FastAPI alike.
- **Testable:** `pyevp.testing` ships a fake issuer and a fake browser, so your application's tests
  need no network access.
- **Small:** the only required dependencies are [joserfc] and idna; DNS and HTTP are pluggable.

```{toctree}
:maxdepth: 2
:caption: Getting started

quickstart
concepts
```

```{toctree}
:maxdepth: 1
:caption: Guides

guides/frameworks
guides/spa
guides/password-recovery
guides/testing
guides/replay
guides/observability
guides/transport
guides/cli
guides/issuers
guides/issuer-operations
```

```{toctree}
:maxdepth: 1
:caption: Reference

api
compatibility
Changelog <https://github.com/gaato/pyevp/blob/main/CHANGELOG.md>
```

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification
[joserfc]: https://jose.authlib.org/
