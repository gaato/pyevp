# Changelog

All notable changes to PyEVP are recorded here. The format follows
[Keep a Changelog]. While the protocol is a draft, any release may contain breaking changes;
see the [compatibility policy].

## [Unreleased]

### Relying party

- A synchronous `Verifier` given an asynchronous replay guard accepted every replay: the guard's
  unawaited answer counted as "not seen before". This was so in 0.1.0. Synchronous calls now
  refuse asynchronous ports with `TypeError`, up front where it can be told and otherwise when
  the port answers; the same holds for nonce stores, caches and `discover`.
- `verification_steps` takes a `clock` instead of `now`, and itself refuses a token that expired
  while it was being marked used, which drivers had to do before.
- `Profile.metadata_path` is gone, since the path is fixed: it is `discovery.METADATA_PATH`, and
  `discovery.metadata_url` takes only the issuer.
- `Verifier.verify_submission` (and the async one) verifies the token a form submitted, taking
  its nonce from a `NonceStore`. Without a token it returns `None` and leaves the store alone.
  Otherwise the nonce the token presents is used up, whether or not the token verifies, and a
  nonce the store did not issue, or that was used, is `nonce_mismatch`, reported to observers
  before anything else is checked.
- `SessionNonces` keeps the nonces in any session with `get` and item assignment (Flask,
  Starlette, Django). It holds the last five for ten minutes, so forms open in several tabs can
  all be verified, where the session used to hold one nonce and only the tab opened last
  worked. `token_input` renders the hidden input as HTML that templates insert as is.
- The Django helpers (`get_nonce`, `verify_request`, the template tag) are built on these, and
  so are all the examples, which used to consume the nonce even without a token and disagreed
  on what a missing nonce meant. The SPA example's cookie now uses the `__Host-` prefix.
- `allowed_issuers=` on `Verifier` and `AsyncVerifier` accepts tokens only from the issuers
  listed. Any other is refused as `PolicyError` with the new code `issuer_not_allowed`, before
  any DNS lookup or HTTP request. The demo's own resolver wrapper is gone.

### Issuer

#### Changed

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
- The issuer reads the body itself, only once the request is worth reading and no further than
  it accepts: pass a function that reads it, such as Django's `request.read`, or to
  `aissuance_response` an asynchronous iterable such as Starlette's `request.stream()`. Bytes
  work too. A guard whose `mark_used` returned an awaitable to `issuance_response` let replays
  through; that is now a `TypeError`.
- `IssuerSite` routes issuance and the JWKS where the issuer's URLs say. Its `issuance_path`
  and `jwks_path` only need setting without an `Issuer`, and `metadata_path` and
  `web_identity_path` are gone, being fixed. So that every framework routes them as written,
  `Issuer` refuses endpoint URLs whose path encodes `/` or contains `<`, `>`, `{` or `}`.

#### Added

- `Issuer.accounts_response` answers Chrome's FedCM accounts request: it checks
  `Sec-Fetch-Dest`, lists only valid addresses in `email_domains`, and is never cached.
- `Issuer.metadata_response`, `Issuer.jwks_response` and `web_identity_response` serve the
  documents with `Cache-Control: public, max-age=300`.
- `login_status_headers` gives the FedCM `Set-Login` header.
- `Issuer.issuance_path` and `jwks_path`, and the constants `METADATA_PATH` and
  `WEB_IDENTITY_PATH`, for routing.

#### Removed

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
