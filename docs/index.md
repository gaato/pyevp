# PyEVP

Python library for the **Email Verification Protocol** (EVP). With EVP, the browser obtains a
token from the user's email provider proving that the user controls an address, and puts it in
your sign-up or sign-in form. Your server verifies the token, so no confirmation email
round-trip is needed.

- **Verifying addresses on your site** (relying party): start with the {doc}`quickstart`.
- **Issuing tokens for your own mail domains** (issuer): start with
  {doc}`guides/issuer-operations`.

Chrome sends tokens with `chrome://flags/#email-verification-protocol` enabled or on a site
registered for the origin trial; other browsers send none. Try it at <https://pyevp.dev/demo>.

```{warning}
**Alpha.** The protocol ([draft-hardt-email-verification], [WICG Email Verification API]) is
still changing. Every moving part is isolated in a versioned {doc}`profile <concepts>`.
```

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
guides/issuer-operations
guides/issuer-policy
guides/issuer-django
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
