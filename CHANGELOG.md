# Changelog

All notable changes to PyEVP are recorded here. The format follows
[Keep a Changelog]. While the protocol is a draft, any release may contain breaking changes;
see the [compatibility policy].

## [Unreleased]

### Changed

- The issuer answers its endpoints itself, so that web frameworks only pass requests in and
  send responses back. `Issuer.issuance_response` (and `aissuance_response`) takes the
  request's method, headers and body and the signed-in user's addresses (`user_emails`, a
  collection or a function), and checks that the user controls the requested address. It
  compares addresses case-insensitively and only ASCII ones, as `IssuerSite.owns` did, so the
  examples' own comparisons are gone. Every refusal is a response; nothing is raised.
- The replay guard records a request only after the user is found to control the address, so
  that requests from users who are not signed in neither fill the store nor use up a request
  that would work after signing in. A signature's `expires`, when earlier than `created` plus
  the maximum age, is now the request's deadline, and a request that goes stale while the
  user's addresses are looked up is refused, with or without a replay guard.
- Requests over 16 KiB (`MAX_REQUEST_BODY`) are refused from `Content-Length`, or their size,
  before the signature is checked, the same way in every framework.
- `IssuanceResponse` is renamed `IssuerResponse` and moved to `pyevp.issuer.response`.
- Observers get one `IssuanceEvent` per request: `stage` is `"request"`, `"ownership"` or
  `"issue"`, and the new `detail` says why a request was refused (without the address). Refusals
  are also logged at `DEBUG`.
- The Django `IssuanceView` answers every method through the issuer, `AccountsView` lists only
  addresses the issuer would issue for, and `IssuerSite` refuses an asynchronous replay guard
  at startup.

### Added

- `Issuer.accounts_response` answers Chrome's FedCM accounts request: it checks
  `Sec-Fetch-Dest`, lists only valid addresses in `email_domains`, and is never cached.
- `Issuer.metadata_response`, `Issuer.jwks_response` and `web_identity_response` serve the
  documents with `Cache-Control: public, max-age=300`.
- `login_status_headers` gives the FedCM `Set-Login` header.
- The Django deployment check `pyevp.W003` warns when `DATA_UPLOAD_MAX_MEMORY_SIZE` is too small
  for issuance requests.

### Removed

- `Issuer.parse_request`, `aparse_request`, `issue` and `success_response`: there is no way to
  issue an EVT without the ownership check. `IssuanceRequest`, `IssuanceError` and
  `accounts_document` are no longer exported, and `IssuerSite.owns` is gone.

## [0.1.0] - 2026-10-04

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

[Unreleased]: https://github.com/gaato/pyevp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gaato/pyevp/releases/tag/v0.1.0
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[compatibility policy]: https://docs.pyevp.dev/en/latest/compatibility.html
