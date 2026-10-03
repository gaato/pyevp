# pyevp.dev site, relying-party demo and demo provider

One container serves the landing page, an EVP relying-party demo on its own page,
and a demo email provider:

| Host | What |
|---|---|
| `pyevp.dev` | The landing page, `/demo` relying-party demo, and the FedCM `/.well-known/web-identity` for the whole site |
| `mail.pyevp.dev` | A demo email provider (EVP issuer) with one account, `demo@pyevp.dev` |
| `demo.pyevp.dev` | Legacy host; permanently redirects to `https://pyevp.dev/demo` |

Visitors start at `https://pyevp.dev/demo`. The default path is to sign in at
`https://mail.pyevp.dev/` and use `demo@pyevp.dev`; Gmail is an alternative when the
visitor is signed in to Google in the same Chrome profile.
The relying party and provider are same-site (both under `pyevp.dev`), unlike most real
deployments, where they are cross-site.

Chrome reads exactly one `/.well-known/web-identity` per registrable domain, and it names a
single `accounts_endpoint`. So `pyevp.dev` can host only one issuer, and this is it: the nightly
interop test (`interop/`) runs against it too.

Anyone can sign in as `demo@pyevp.dev`. A token from this provider proves only that someone
pressed the button. Do not accept it anywhere but a demo.

The [rowan.fyi](https://rowan.fyi/made/email-verification/) and
[verifyemails.vercel.app](https://verifyemails.vercel.app/) demos came first. Some ideas from
rowan.fyi's provider are reimplemented here: one-button sign-in, a `Sec-Fetch-Site` check
against CSRF, and announcing sign-in with both `Set-Login` and `setStatus()`. No code or text
was copied.

## DNS

```
pyevp.dev                         -> this container (Cloudflare Tunnel)
mail.pyevp.dev                    -> this container (Cloudflare Tunnel)
demo.pyevp.dev                    -> this container (Cloudflare Tunnel; legacy redirect)
_email-verification.pyevp.dev TXT "iss=mail.pyevp.dev"
pyevp.dev MX 0 .                  (null MX: the address receives no mail)
pyevp.dev TXT "v=spf1 -all"
_dmarc.pyevp.dev TXT "v=DMARC1; p=reject"
```

Rate limiting is done per client IP at Cloudflare, not in the app: behind the tunnel every
request comes from the same connector address.

## Configuration

| Variable | Default | |
|---|---|---|
| `EVP_SIGNING_JWK` | required | Private signing key as a JWK JSON string (`pyevp issuer keygen`) |
| `SESSION_SECRET` | required | Key for the separate site and provider signed session cookies |
| `EVP_SITE_HOST` | `pyevp.dev` | Host of the landing page |
| `EVP_MAIL_HOST` | `mail.pyevp.dev` | Host of the provider; the issuer is `https://<this>` |
| `EVP_EMAIL_DOMAIN` | `pyevp.dev` | The demo address is `demo@<this>` |
| `EVP_ALLOWED_ISSUERS` | `https://accounts.google.com https://<mail host>` | Space-separated issuer origins accepted by the relying party; an empty value accepts none |
| `EVP_LEGACY_DEMO_HOST` | `demo.pyevp.dev` | Host that permanently redirects to `https://<site host>/demo` |
| `EVP_EXAMPLES_DIR` | Repository `examples/` | Root containing the three marked framework examples; the image sets this to `/app/examples` |
| `EVP_ORIGIN_TRIAL_TOKEN` | unset | Chrome origin trial token for EVP. When set, `/demo` and the `POST /verify` result page carry `<meta http-equiv="origin-trial">`, and step 1 says Chrome 150 or later works without the flag |
| `BUILD_SHA` | `unknown` | Reported by `/me`; the image sets it at build time |
| `EVP_DEV` | unset | `1` allows a missing key (an ephemeral one is generated) or session secret, and a missing stylesheet. Never set it in production |

The app refuses to start without `EVP_SIGNING_JWK` and `SESSION_SECRET` unless `EVP_DEV=1`:
a key generated on every start would change the JWKS on every auto-update restart.

The container listens on port 8080.

## Routes

`GET /healthz` answers `200 ok` on any host, so that the container health check (which calls
`127.0.0.1:8080`) works. Any other request for an unknown host gets 404.

### `pyevp.dev`

| Route | Response |
|---|---|
| `GET /` | Landing page rendered once at startup; no nonce or session |
| `GET /demo` | Demo page rendered per request, with a fresh nonce in the form and site session |
| `POST /verify` | Demo page with the verification result: verified email and issuer, stable error code and explanation (400), expired session (400), or missing-token explanation (200) |
| `GET /robots.txt` | Allows all crawlers and names `https://<site host>/sitemap.xml` |
| `GET /sitemap.xml` | `https://<site host>/` and `https://<site host>/demo` |
| `GET /.well-known/web-identity` | `web_identity_document(accounts_endpoint="https://<mail host>/fedcm/accounts", login_url="https://<mail host>/login")`, `application/json` |

The relying-party session cookie is host-only on the site host, named `pyevp_site_session`,
with `SameSite=Lax; Secure; HttpOnly`. It is separate from the mail host's cookie. The nonce
is consumed on submission, whether verification succeeds or fails; "Start over" links to
`/demo` to get a new nonce. Demo and verification responses use `Cache-Control: no-store`.
Each page has its own title, description, canonical URL (`https://<site host>/` or
`https://<site host>/demo`; the result page uses the demo's), Open Graph tags and
`twitter:card=summary`.
The landing route does not read or update the site session, even when the browser already
has a site cookie.
The verifier's audience is `https://<site host>`.

Discovery can otherwise fetch HTTPS URLs chosen by whoever controls the email domain in
the token, before checking the issuer signature. `AllowedIssuers` rejects unlisted issuers
at the DNS step, before any HTTP fetch. The verifier also uses `InMemoryReplayGuard` and
`LoggingObserver`. Run one process only: replay protection is in memory. The app sets
security headers but deliberately omits header-delivered CSP, which hides HTML nonce
attributes that EVP needs to read.

### Demo flow and token arrival

The page uses semantic HTML and named hooks for its three steps: `#demo-browser`,
`#demo-provider`, and `#demo-verify`, followed by `#demo-result` (`role="status"`,
`aria-live="polite"`). Chrome/Chromium 150 or newer (desktop or Android) with
`chrome://flags/#email-verification-protocol` enabled is the suggested browser. With
`EVP_ORIGIN_TRIAL_TOKEN` set, the page joins the origin trial, so Chrome 150 or later works
without the flag; the flag is then mentioned only when no token arrived. A soft
client-side notice uses the secure context and the UA brands/version; it never
blocks submission and cannot detect whether EVP is enabled. The provider sign-in state
is not queried or displayed by the relying party. The email field starts empty, with the
demo address only as a placeholder: Chrome asks the provider for a token only after the
visitor types an address or picks one from autofill, so a pre-filled value would send none.

Chrome fills the hidden `autocomplete="email-verification-token"` input on submission,
before submit handlers run. The inline script checks it at each submit attempt. If empty,
it prevents submission, says "Waiting for your email provider…", sets `aria-busy` on the
button, and retries via `form.requestSubmit(submitter)` every 400 ms. A token lets submission
proceed immediately with "Token received, verifying…". After 8 seconds from the first attempt,
it submits even without a token so the server can explain likely causes. The button stays
enabled; repeat clicks share the deadline and replace the pending timer. Without JavaScript
(or without `requestSubmit`) the ordinary form still submits. This is a bounded workaround
for [WICG/email-verification issue #42](https://github.com/WICG/email-verification/issues/42),
not an EVP feature detection API.

### Verification trace

Token verification results include elapsed milliseconds, six trace rows with `passed`,
`failed`, or `not run`, and an exhaustive `ErrorCode` mapping in `verification_trace.py`:

1. Parse the token.
2. Key binding: audience, nonce, freshness, `sd_hash`, holder signature.
3. DNS `_email-verification.<domain>`.
4. Issuer metadata.
5. JWKS.
6. Issuer signature and claims, including the email match and replay protection.

These are grouped display rows. The library actually checks preliminary EVT claims before
key binding, and the email match before DNS; the holder signature also precedes the other
key-binding checks. An early claims failure marks the claims row failed and leaves network
rows not run; key binding is passed only if it ran. All rows pass only after full success.
Public offline checks disambiguate shared error codes after a failure; recorded port/cache
activity identifies DNS, metadata, and JWKS failures without parsing exception messages.

DNS and HTTP recording wrappers use the public async ports. The resolver recorder sits
inside `AllowedIssuers`, so a completed DNS lookup may be recorded as passed while issuer
policy fails the DNS row. Lookup outcomes describe I/O, not document validation. Each
lookup includes its name/URL, outcome, and elapsed milliseconds. A request-local contextvar
isolates records. One long-lived verifier preserves its caches, refresh throttling, replay
guard, and logging observer. A public cache wrapper tracks stages even for cached documents;
cache hits produce no HTTP fetch entries. No library internals are accessed.

A `<details>` panel shows only EVT and KB-JWT payload claims from `pyevp.token.parse_token`,
labeled "decoded for display". Decoding is not verification. Raw tokens, JWT headers, and
signatures are not displayed. All claims, errors, results, and lookup targets are escaped.
Missing tokens produce likely causes (provider sign-in, token arrival, EVP enablement) and
all results offer a "Start over" link to `/demo`.

### Legacy host (`EVP_LEGACY_DEMO_HOST`)

| Route | Response |
|---|---|
| Every path and HTTP method, except `GET /healthz` | `301` with `Location: https://<site host>/demo`; original path and query are discarded |

### `mail.pyevp.dev`

Paths follow `examples/issuer_fastapi`.

| Route | Response |
|---|---|
| `GET /` and `GET /login` | The provider page: what this is, and a single "Sign in as demo@pyevp.dev" (or "Sign out") button. `/login` is the FedCM `login_url` |
| `POST /login` | No form fields. Starts the session for `demo@pyevp.dev`, answers with the provider page, `Set-Login: logged-in`, and a `navigator.login.setStatus("logged-in")` call |
| `POST /logout` | Clears the session, answers with the provider page and `Set-Login: logged-out` (plus `setStatus`) |
| `GET /robots.txt` | Disallows all crawlers |
| `GET /me` | `{"email": "demo@pyevp.dev" or null, "issued": <tokens issued in this session>, "build_sha": "..."}`, `Cache-Control: no-store` |
| `GET /.well-known/email-verification` | Issuer metadata |
| `GET /email-verification/jwks` | JWKS |
| `GET /fedcm/accounts` | FedCM accounts: requires `Sec-Fetch-Dest: webidentity`; the signed-in address or an empty list; `Cache-Control: no-store`; no CORS headers |
| `POST /email-verification/issuance` | Issuance, as in `examples/issuer_fastapi`. The email in the request must equal the session's address, compared case-insensitively |

Every response on the mail host, including `/healthz` and errors, carries
`X-Robots-Tag: noindex`, and the provider page also has `<meta name="robots" content="noindex">`.

`POST /login` and `POST /logout` reject requests whose `Sec-Fetch-Site` is present and not
`same-origin` with 403.

The session cookie is host-only on the mail host, `SameSite=None; Secure; HttpOnly`, and lasts
one hour. Chrome sends it with the FedCM accounts and issuance requests; `SameSite=None`
also supports relying parties on other sites.

Error responses carry no request details.

## Landing page

Templates are Jinja2 (`templates/`). `base.html` shares the header/navigation (home, Demo,
Docs, GitHub) and footer. The landing page, example extraction, Pygments highlighting,
stylesheet loading and provider-page rendering happen once at startup. `/demo` is rendered
per request. The stylesheet is Tailwind CSS v4
with daisyUI 5 (default `light` and `dark` themes, following `prefers-color-scheme`), built
without Node by `scripts/build-css.sh` and inlined into each page. Code is highlighted with
Pygments on the server, with a light and a dark style.

The framework examples on the landing page are cut from the real examples, between marker
comments:

```python
# landing:start
...
# landing:end
```

| Tab | File |
|---|---|
| FastAPI | `examples/fastapi/app.py` |
| Flask | `examples/flask/app.py` |
| Django | `examples/django/views.py` |

Each file has exactly one marked region. The app refuses to start if one is missing, and a
test checks all of them, so the page cannot drift from code that CI runs.

Without JavaScript the examples are stacked sections with headings. A short inline script turns
them into WAI-ARIA tabs.

## Development

```fish
scripts/build-css.sh static/site.css   # downloads the pinned Tailwind and daisyUI once
env EVP_DEV=1 uv run uvicorn app:app --port 8080
curl -H 'Host: pyevp.dev' localhost:8080/
uv run pytest
```

`.dev` is on the HSTS preload list, so Chrome only loads `pyevp.dev` over HTTPS. To look at
the pages in a local Chrome, serve them with a self-signed certificate and map the hosts:

```fish
env EVP_DEV=1 uv run uvicorn app:app --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
google-chrome --ignore-certificate-errors \
    --host-resolver-rules="MAP pyevp.dev 127.0.0.1:8443, MAP mail.pyevp.dev 127.0.0.1:8443" \
    https://pyevp.dev/demo
```

### Updating Tailwind and daisyUI

The versions are pinned at the top of `scripts/build-css.sh`, each download with a SHA256.
Renovate bumps `TAILWIND_VERSION` and `DAISYUI_VERSION` but cannot update the hashes, so after
a bump the script fails with a SHA256 mismatch until they are fixed:

```sh
scripts/build-css.sh --print-hashes   # downloads the pinned versions, prints the *_SHA256 lines
```

Paste the output over the `*_SHA256` lines in the script, then rerun
`scripts/build-css.sh static/site.css` and check the page.
