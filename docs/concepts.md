# Concepts

## The flow

1. Your page renders a form with a nonce (see {doc}`quickstart`).
2. The user picks an address from autofill. The browser looks up the issuer for the address's
   domain, obtains an **Email Verification Token (EVT)** from it, and binds it to your origin and
   nonce with a **key-binding JWT (KB-JWT)**.
3. The form is submitted with `evt=<EVT>~<KB-JWT>`.
4. Your server verifies it.

The EVT is signed by the issuer and contains `iss`, `iat`, `email`, `email_verified` and the
browser's public key (`cnf.jwk`). The KB-JWT is signed with that browser key and contains `aud`
(your origin), `nonce`, `iat` and `sd_hash` (a hash of the EVT).

## Verification

{func}`pyevp.core.verification_steps` checks, in this order:

1. **Offline checks.** It parses the token, then checks the EVT's header and claims and its
   freshness. It verifies the KB-JWT signature against `cnf.jwk`, and checks `aud`, `nonce`, `iat`
   and `sd_hash`. It also compares the submitted email when one is given, and, with
   `allowed_issuers`, refuses a token whose `iss` is not listed.
2. **Discovery.** It looks up the DNS TXT record `_email-verification.<domain>`, which must hold
   exactly one `iss=` entry. The token's `iss` must equal that issuer.
3. **Issuer metadata and keys.** It fetches `<issuer>/.well-known/email-verification` and then
   the `jwks_uri` it names. These are cached. If no key verifies the token, the keys are fetched
   again once, rate-limited, in case they were rotated.
4. **EVT signature.**
5. **Replay protection**, if enabled.

Everything that can be checked without the network is checked first. The only hosts ever
contacted are derived from DNS, never from the token.

## Sans-I/O core

The verification logic in {mod}`pyevp.core` performs no I/O. It is a generator that *yields*
requests, {class}`~pyevp.core.ResolveTxt`, {class}`~pyevp.core.FetchJson` and
{class}`~pyevp.core.MarkUsed`, and receives their results. The drivers {class}`pyevp.Verifier` and
{class}`pyevp.AsyncVerifier` only answer those requests through injected *ports*:

- {class}`~pyevp.TxtResolver`
- {class}`~pyevp.JsonFetcher`
- {class}`~pyevp.ReplayGuard`
- their async counterparts

As a result:

- the same logic serves synchronous Django views and asynchronous FastAPI endpoints;
- DNS, HTTP, caches and replay stores can be swapped without touching verification;
- tests can drive the generator by hand or plug in the fakes from {mod}`pyevp.testing`.

(profiles)=

## Profiles

The protocol is still moving, and deployed issuers lag behind the drafts. Gmail, for instance,
signs with `EdDSA` and publishes keys without `kid`, which the latest draft forbids. Every such
choice lives in a {class}`pyevp.Profile`:

| Preset | Purpose |
|---|---|
| `compat-2026-10` (default) | Accepts what Chrome and Gmail ship today as well as the -02 draft |
| `draft-hardt-02` | Strict reading of draft-hardt-email-verification -02 |

```python
from datetime import timedelta
from pyevp import Profile

strict = Profile.named("draft-hardt-02")
short_lived = Profile.compat_2026_10().replace(max_token_age=timedelta(minutes=2))
```

Following a spec change usually means adding a new preset rather than changing an existing one,
so that you can choose when to switch. Run `pyevp discover <domain> --profile <name>` to see how an issuer fares
under a profile.
