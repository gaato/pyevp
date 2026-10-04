# Quickstart

## Install

```sh
pip install "pyevp[dns,httpx2]"
```

`[dns,httpx2]` adds dnspython and httpx2, which `Verifier.default()` uses for DNS and HTTPS. See
{doc}`guides/transport` for httpx, DNS over HTTPS and other options.

## 1. Put a nonce on the form

When you render the form, issue a nonce into the user's session (Flask's, Starlette's or
Django's) and add a hidden field for the browser to fill with the token:

```python
from pyevp import SessionNonces, token_input

nonce = SessionNonces(session).issue()
hidden_input = token_input(nonce)  # HTML that Jinja and Django templates insert as is
```

```html
<input type="email" name="email" autocomplete="email">
<input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
```

Create one {class}`~pyevp.SessionNonces` per request, and issue a nonce only on pages that have
a form, since storing it creates a session. Without a server session, see {doc}`guides/spa`.

The `nonce` must be an HTML attribute; the browser ignores one set as a DOM property.

### Fitting EVP into an existing form

- The email field needs `autocomplete="email"`, not `off`, and must start empty: a pre-filled
  address gets no token.
- Chrome fills `evt` only as the form is submitted, just before `submit` handlers run. Check it on
  the server, not in client-side validation. A script that sends the form must do so from the
  `submit` handler, with the `evt` field.
- Chrome asks the email provider when focus leaves the email field, so a quick submit can carry
  an empty `evt`. To wait, a `submit` handler can cancel the submission while `evt` is empty and
  retry with `form.requestSubmit()` up to a deadline; the [demo](https://pyevp.dev/demo) retries
  every 400 ms for 8 seconds ([WICG/email-verification#42]).

[WICG/email-verification#42]: https://github.com/WICG/email-verification/issues/42

## 2. Verify on submit

Create the verifier once, with your page's origin as the audience:

```python
from pyevp import EVPError, Verifier

verifier = Verifier.default(audience="https://example.com")
```

Call `verifier.close()` on shutdown (`await verifier.aclose()` for `AsyncVerifier`), or use it
as a context manager.

By default, any issuer that the email domain's DNS names is accepted. To accept only providers
you know, list them, for example `allowed_issuers=["https://accounts.google.com"]`; other tokens
are refused with `issuer_not_allowed` before anything is looked up.

Then, in the form handler:

```python
try:
    result = verifier.verify_submission(
        form.get("evt"), nonces=SessionNonces(session), email=form["email"]
    )
except EVPError as exc:
    log.info("EVP rejected: %s", exc.code)  # fall back to a confirmation email
else:
    if result is None:
        ...  # no token: fall back to a confirmation email
    else:
        mark_verified(result.email)  # result.issuer, result.claims, ...
```

Each nonce works once. `AsyncVerifier` has the same API: `await verifier.verify_submission(...)`.
To pass the nonce yourself, use {meth}`~pyevp.Verifier.verify`.

`result.email` may differ from the submitted address in case, so look up the account with
{meth}`verifier.profile.emails_match() <pyevp.Profile.emails_match>`.

(handle-failures)=

## 3. Handle failures

A rejected token raises a {class}`~pyevp.TokenError`, {class}`~pyevp.DiscoveryError` or
{class}`~pyevp.PolicyError`, all {class}`~pyevp.EVPError`s whose `code` says why. Errors from
your own cache or replay guard propagate unchanged.

Whatever the code, the safe default is to fall back to your existing verification flow. The
code tells you whether the user can retry and whether your side needs attention:

| Code | Usually means | What to do |
|---|---|---|
| `nonce_mismatch`, `token_expired` | Stale form: expired session, double submit, or older than the last five forms or `max_token_age` | Render a fresh form, or fall back |
| `token_not_yet_valid` | Clock skew between the browser and your server | Fall back; if frequent, check your server clock |
| `email_mismatch` | The email field was edited after picking an address | Ask the user to pick the address again |
| `audience_mismatch` | `audience` differs from the page's origin | Fix your configuration (proxies, hostnames) |
| `issuer_unreachable` | DNS or HTTPS to the issuer failed; may be transient | Fall back; monitor the rate |
| `issuer_discovery_failed`, `metadata_invalid`, `key_not_found`, `unsupported_alg`, `bad_type` | No usable issuer for the domain, or its metadata or keys are broken, rotating or refused by your profile | Fall back; `pyevp discover <domain>` shows details |
| `email_not_verified`, `issuer_not_allowed` | The issuer does not vouch for the address, or is not in your `allowed_issuers` | Fall back |
| `token_replayed` | The token was already accepted once | Reject; this is a resubmission or an attack |
| `malformed_token` | The field did not contain an EVP token | Fall back; if frequent, check the form markup |
| `issuer_mismatch`, `evt_signature_invalid`, `kb_signature_invalid`, `sd_hash_mismatch` | Forged or tampered token | Fall back and log; do not trust the address |

Treat unknown codes as "fall back".

```{important}
If the session lives in a signed cookie, such as Starlette's `SessionMiddleware`, taking the
nonce out does not make it single-use: the old cookie can be sent again. Enable
{doc}`replay protection <guides/replay>`.
```

## Try it in Chrome

1. Enable `chrome://flags/#email-verification-protocol`, or start Chrome with
   `--enable-features=EmailVerificationProtocol`. Visitors need neither if your page carries a
   token from Chrome's origin trial (`<meta http-equiv="origin-trial" content="...">`).
2. Sign in to Google in the same Chrome profile.
3. Open your form over HTTPS or on `localhost`, at the `audience` origin, pick your Gmail
   address and move to the next field. Chrome asks once whether to verify it automatically.

## Next

- {doc}`guides/frameworks`: FastAPI, Flask, Django and other integrations
- {doc}`guides/replay`: one use per token
- {doc}`guides/testing`: test your application without a browser or network
- {doc}`guides/transport`: DNS, HTTP, caching and private networks
