# Concepts

## The flow

1. Your page renders a form with a nonce (see {doc}`quickstart`).
2. The user types or picks an address. The browser looks up the issuer for the address's
   domain, obtains an **Email Verification Token (EVT)** from it, and binds it to your origin and
   nonce with a **key-binding JWT (KB-JWT)**.
3. The form is submitted with `evt=<EVT>~<KB-JWT>`.
4. Your server verifies it.

The EVT is signed by the issuer and contains `iss`, `iat`, `email`, `email_verified` and the
browser's public key (`cnf.jwk`). The KB-JWT is signed with that browser key and contains `aud`
(your origin), `nonce`, `iat` and `sd_hash` (a hash of the EVT).

## What the user sees

The user must be signed in to their email provider in the same browser. Before the first token
for an address, Chrome asks once whether to verify that email automatically. After that, nothing
is shown: Chrome starts when focus leaves the email field and attaches the token when the form is
submitted. When anything fails, the form arrives without a token and the page is not told why.

## Trust model

An EVT means the issuer vouches that the browser's user controls the address, as a click on a
link sent there would. The KB-JWT ties it to your origin and nonce, so it cannot be replayed on
another site.

Anyone who controls a domain's DNS names its issuer, with a `_email-verification` TXT record. A
token is therefore as trustworthy as the domain's owner, just as a confirmation email is as
trustworthy as the domain's mail server. That is why any issuer is accepted by default. Pass
`allowed_issuers` when you want addresses only from providers you know, such as your company's
identity provider, or want the verifier to contact only those hosts (see
{ref}`private networks <ssrf>`).

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

The only hosts ever contacted are derived from DNS, never from the token.

## Sans-I/O core

{func}`~pyevp.core.verification_steps` performs no I/O: it is a generator that yields requests
({class}`~pyevp.core.ResolveTxt`, {class}`~pyevp.core.FetchJson`, {class}`~pyevp.core.MarkUsed`)
and receives their results. {class}`pyevp.Verifier` and {class}`pyevp.AsyncVerifier` answer them
through the ports you inject ({class}`~pyevp.TxtResolver`, {class}`~pyevp.JsonFetcher`,
{class}`~pyevp.ReplayGuard` and their async counterparts), so the same logic serves sync and
async code, and tests can use the fakes in {mod}`pyevp.testing`.

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

Spec changes usually arrive as new presets, so you choose when to switch. Run
`pyevp discover <domain> --profile <name>` to see how an issuer fares under a profile.
