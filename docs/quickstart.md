# Quickstart

## Install

```sh
pip install "pyevp[dns,httpx2]"
```

`[dns,httpx2]` adds dnspython and httpx2, which `Verifier.default()` uses for DNS and HTTPS. See
{doc}`guides/transport` for httpx, DNS over HTTPS and other options.

## 1. Put a nonce on the form

Generate a nonce each time you render the page, keep it in the user's session, and add two
inputs to the form: the email field the user fills in, and a hidden field the browser fills with
the token.

```python
from pyevp import generate_nonce

nonce = generate_nonce()
session["evp_nonce"] = nonce
```

```html
<input type="email" name="email" autocomplete="email">
<input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
```

The `nonce` must be a content attribute in the HTML. Frameworks that set it as a DOM property
are not picked up by the browser. React 19 renders the `nonce` prop as a content attribute.

Chrome writes the token into the hidden field only when the form is submitted. Before that,
page scripts read an empty value, so check the token on the server, not in client-side
validation.

The session holds one nonce, so all forms on a page share it. For the same reason, only the tab
opened last can be verified; forms in older tabs fall back to your usual flow. Storing the nonce
gives each visitor a session, so add the inputs only to pages that have a form. An API without
server sessions can keep the nonce in a cookie instead; see {doc}`guides/spa`.

### Fitting EVP into an existing form

- The email field needs `autocomplete="email"`. With `autocomplete="off"` the browser does not
  offer verified addresses.
- Leave the field empty. Chrome asks the email provider for a token only after the user types an
  address or picks one from autofill, so a pre-filled value sends none.
- Submit through the form. The token is filled in as part of the form's submission, so a script
  that sends the fields with `fetch()` from a click handler gets none. Send from the form's
  `submit` handler instead, including the `evt` field, as `FormData` if your server reads form
  fields.

## 2. Verify on submit

Create the verifier once, with your origin as the audience:

```python
from pyevp import EVPError, Verifier

verifier = Verifier.default(audience="https://example.com")
```

The verifier keeps an HTTP client open. On shutdown, call `verifier.close()` (`await
verifier.aclose()` for `AsyncVerifier`), or use it as a context manager. It closes only what
`default()` created: a resolver, fetcher or HTTP client you pass in is yours to close.

Then, in the form handler:

```python
token = form.get("evt")
# Single use, once a token arrives; without one, the browser did not use the nonce.
nonce = session.pop("evp_nonce", None) if token else None
if token and nonce:
    try:
        result = verifier.verify(token, nonce=nonce, email=form["email"])
    except EVPError as exc:
        log.info("EVP rejected: %s", exc.code)  # fall back to a confirmation email
    else:
        mark_verified(result.email)  # result.issuer, result.claims, ...
```

Keeping the nonce when no token arrived matters when the page is not rendered again, for
example a form sent with `fetch()`: its next submission still has a nonce to check.

`AsyncVerifier` has the same API: `await verifier.verify(...)`.

`result.email` is the address the issuer asserted. Under the default profile it may differ from
the submitted one in case. To find the account, compare addresses with
{meth}`verifier.profile.emails_match() <pyevp.Profile.emails_match>`, which applies the same rule
as verification: the local part is case-folded, and domains are compared as DNS names, so
`faß.example` and `fass.example` stay different.

(handle-failures)=

## 3. Handle failures

A rejected token raises a subclass of {class}`pyevp.EVPError` whose {class}`pyevp.ErrorCode`
says why:

| Exception | Meaning | Typical codes |
|---|---|---|
| {class}`~pyevp.TokenError` | Malformed, stale, mis-bound or badly signed token | `nonce_mismatch`, `token_expired`, `token_replayed` |
| {class}`~pyevp.DiscoveryError` | The issuer could not be discovered or used | `issuer_mismatch`, `issuer_unreachable` |
| {class}`~pyevp.PolicyError` | Not acceptable to your profile; checked before the signature, so not a sign of authenticity | `email_mismatch`, `email_not_verified` |

`issuer_unreachable` may be transient. Everything else means "do not trust this token".
Exceptions from your own cache or replay guard are not `EVPError`s; they propagate unchanged,
so an outage on your side does not look like a rejected token. EVP is a
progressive enhancement: when there is no token, or it is rejected, fall back to your existing
verification flow.

Whatever the code, the safe default is the fallback. The codes tell you whether the user can
simply try again and whether something on your side needs attention:

| Code | Usually means | What to do |
|---|---|---|
| `nonce_mismatch` | The session expired or the form was submitted twice | Render a fresh form, or fall back |
| `token_expired` | The user took longer than `max_token_age` to submit | Render a fresh form, or fall back |
| `token_not_yet_valid` | Clock skew between the browser and your server | Fall back; if frequent, check your server clock |
| `email_mismatch` | The email field was edited after picking an address | Ask the user to pick the address again |
| `audience_mismatch` | `audience` differs from the page's origin | Fix your configuration (proxies, hostnames) |
| `issuer_unreachable` | DNS or HTTPS to the issuer failed; may be transient | Fall back; monitor the rate |
| `issuer_discovery_failed` | The email domain has no usable `_email-verification` record | Fall back |
| `metadata_invalid`, `key_not_found` | The issuer's metadata or keys are broken or rotating | Fall back; `pyevp discover <domain>` shows details |
| `unsupported_alg`, `bad_type` | The issuer signs in a way your profile does not accept | Fall back; compare with `pyevp discover` |
| `email_not_verified` | The issuer does not vouch for the address | Fall back |
| `token_replayed` | The token was already accepted once | Reject; this is a resubmission or an attack |
| `malformed_token` | The field did not contain an EVP token | Fall back; if frequent, check the form markup |
| `issuer_mismatch`, `evt_signature_invalid`, `kb_signature_invalid`, `sd_hash_mismatch` | Forged or tampered token | Fall back and log; do not trust the address |

Codes may be added in minor releases, so treat unknown codes as "fall back".

```{important}
If the nonce is stored client-side, in a session kept in a signed cookie such as Starlette's
`SessionMiddleware` or in a cookie of its own, popping it does not make it single-use. Enable
{doc}`replay protection <guides/replay>`.
```
