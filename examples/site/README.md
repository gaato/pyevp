# pyevp.dev

One Starlette app in one container serves the project's landing page, a relying-party demo
built on pyevp, and a demo email provider (EVP issuer) with a single public account,
`demo@pyevp.dev`. Visitors verify that address, or their Gmail address if Chrome is signed in to
Google. The nightly Chrome interop test ([`interop/`](../../interop/README.md)) uses the same
provider. Anyone can sign in as `demo@pyevp.dev`, so a token from this provider proves only that
someone pressed the button: accept it nowhere but a demo.

## Hosts

- `pyevp.dev`: the landing page, the demo relying party at `/demo`, and the FedCM
  `/.well-known/web-identity` for the whole domain.
- `mail.pyevp.dev`: the demo issuer and its sign-in page. Its paths follow
  `examples/issuer_fastapi`, and `/me` reports the session and the deployed `build_sha`.
- `demo.pyevp.dev`: a legacy host that permanently redirects to `https://pyevp.dev/demo`.

Every host answers `GET /healthz`. Chrome reads one `web-identity` file per registrable
domain, so `pyevp.dev` can host only this one issuer.

All three hosts reach the container through a Cloudflare Tunnel, which also rate-limits by
client IP. `_email-verification.pyevp.dev` has `TXT "iss=mail.pyevp.dev"`; a null MX, SPF
`-all` and DMARC `p=reject` say the domain sends and receives no mail.

## Running locally

From this directory:

```fish
scripts/build-css.sh static/site.css   # downloads the pinned Tailwind and daisyUI once
env EVP_DEV=1 uv run uvicorn app:app --port 8080
curl -H 'Host: pyevp.dev' localhost:8080/
uv run pytest
```

`.dev` is on the HSTS preload list, so to use the pages in Chrome, serve them over TLS with a
self-signed certificate and map the hosts:

```fish
env EVP_DEV=1 uv run uvicorn app:app --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
google-chrome --ignore-certificate-errors \
    --host-resolver-rules="MAP pyevp.dev 127.0.0.1:8443, MAP mail.pyevp.dev 127.0.0.1:8443" \
    https://pyevp.dev/demo
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `EVP_SIGNING_JWK` | required | Issuer private key as a JWK JSON string (`pyevp issuer keygen`) |
| `SESSION_SECRET` | required | Key for the session cookies |
| `EVP_ALLOWED_ISSUERS` | `https://accounts.google.com https://<mail host>` | Space-separated issuers the demo accepts; empty accepts none |
| `EVP_ORIGIN_TRIAL_TOKEN` | unset | Lets Chrome 150+ use EVP without the flag |
| `EVP_SITE_HOST` | `pyevp.dev` | Landing page and demo; the verifier's audience is `https://<this>` |
| `EVP_MAIL_HOST` | `mail.pyevp.dev` | Provider; the issuer is `https://<this>` |
| `EVP_EMAIL_DOMAIN` | `pyevp.dev` | The demo address is `demo@<this>` |
| `EVP_LEGACY_DEMO_HOST` | `demo.pyevp.dev` | Redirects to the demo |
| `EVP_EXAMPLES_DIR` | the repository's `examples/` | Source of the landing-page snippets; the image sets `/app/examples` |
| `BUILD_SHA` | `unknown` | Reported by `/me`; the image build sets it |
| `EVP_DEV` | unset | `1` generates a missing key or secret and tolerates a missing stylesheet; never in production |

Without `EVP_DEV=1` the app refuses to start without a key and secret: a key generated at each start
would change the JWKS on every restart. It listens on port 8080; run one process, as the replay
guard is in memory.

The allowlist is checked before any DNS lookup or fetch, so a visitor cannot make the site
fetch URLs chosen by whoever controls their email domain.

## How the pages are built

The landing page's FastAPI, Flask and Django snippets are cut from `examples/fastapi/app.py`,
`examples/flask/app.py` and `examples/django/views.py`, between `# landing:start` and
`# landing:end` comments. The app refuses to start if a marker is missing and a test checks all
three, so the page shows code that CI runs.

`verification_trace.py` turns the result and the recorded DNS, HTTP and cache activity into
the demo's step-by-step trace. Chrome fills the token only at submission, so the demo's script
waits briefly for it (see the [quickstart](../../docs/quickstart.md)).

## Deployment

`.github/workflows/site-image.yml` builds `ghcr.io/gaato/pyevp-site` from `Containerfile` for
amd64 and arm64. On a push to `main` that touches one of the paths it lists (this directory, the
three example files above, `src/`, `pyproject.toml`, `uv.lock`, `.dockerignore` or the workflow
itself), or on a manual run, it pushes `:latest` and `:sha-<commit>`; pull requests only build.
The host runs `:latest` under podman auto-update, so such a push to `main` is a deploy.
`GET https://mail.pyevp.dev/me` returns the deployed commit as `build_sha`.

## Credits

The [rowan.fyi](https://rowan.fyi/made/email-verification/) and
[verifyemails.vercel.app](https://verifyemails.vercel.app/) demos came first; the one-button
sign-in, the `Sec-Fetch-Site` check and announcing sign-in with both `Set-Login` and
`setStatus()` are reimplemented from rowan.fyi's provider, without copying code or text.
