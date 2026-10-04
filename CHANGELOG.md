# Changelog

All notable changes to PyEVP are recorded here. The format follows
[Keep a Changelog]. While the protocol is a draft, any release may contain breaking changes;
see the [compatibility policy].

## [Unreleased]

The first release.

### Relying party

- `Verifier` and `AsyncVerifier` verify the `<EVT>~<KB-JWT>` token the browser puts in a form.
  The key-binding JWT (audience, nonce, freshness, `sd_hash`, holder signature) is checked before
  any I/O. The issuer is then discovered from the `_email-verification.<domain>` TXT record, and
  its metadata, JWKS and signature are checked.
- Only hosts derived from DNS are contacted, never hosts named in the token. Before connecting,
  the default fetchers check that the host resolves only to public addresses; the
  [transport guide](https://docs.pyevp.dev/en/latest/guides/transport.html#ssrf) explains what
  this check does not catch (DNS rebinding).
- Every rejected token raises an `EVPError` whose `ErrorCode` says why.
- Profile presets `compat-2026-10` (the default) and `draft-hardt-02` hold every point where the
  drafts and deployed issuers differ.
- DNS adapters for dnspython and DNS over HTTPS, HTTP adapters for httpx2 and httpx, and a setup
  that needs only the standard library. `pyevp[dns,httpx2]` installs the adapters that
  `Verifier.default()` uses; `pyevp[all]` installs every optional dependency.
- Caching of issuer metadata and keys, replay guards, and an `Observer` hook for logging and
  metrics.
- `pyevp.testing`: `FakeIssuer`, `FakeBrowser` and in-memory DNS and HTTP, for testing
  applications without network access.
- Django integration (`pyevp[django]`): a template tag for the token input, `verify_request`, a
  cache backed by Django's cache framework and a replay guard backed by a database table.

### Issuer

- `pyevp.issuer.Issuer` validates the browser's signed issuance request, mints EVTs and produces
  the metadata, JWKS and DNS record to publish. The issuance profile `chrome-153` matches what
  Chrome 153 and later send and accept. Email domains can be a fixed collection or a callable
  for domains that change at runtime; names that are not valid domains are refused.
- `pyevp.contrib.django.issuer.IssuerSite` serves an issuer from Django, with the signed-in user
  deciding which addresses get tokens.

### Command line

- `pyevp[cli]` installs the `pyevp` command: `discover` checks a domain's issuer, `inspect`
  decodes a token offline and `verify` verifies one. `pyevp issuer keygen` and
  `pyevp issuer documents` help set up an issuer.

[Unreleased]: https://github.com/gaato/pyevp/commits/main
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[compatibility policy]: https://docs.pyevp.dev/en/latest/compatibility.html
