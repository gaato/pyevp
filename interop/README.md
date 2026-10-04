# Chrome interop test

`chrome_evp.py` runs the whole Email Verification Protocol flow in a real, headless Chrome
against the public demo provider at `https://mail.pyevp.dev`:

1. It checks that the provider is up: `/healthz`, the `pyevp.dev` web-identity file and the
   `_email-verification.pyevp.dev` TXT record.
2. It starts `examples/fastapi` from this checkout as the relying party on `localhost:8001`,
   signs in to the provider as `demo@pyevp.dev` in a fresh profile, and verifies that address.
3. It expects the relying party to answer `verified: true` with issuer `https://mail.pyevp.dev`
   and email `demo@pyevp.dev`.

The relying party uses the library at the checked-out commit; the provider runs whatever image
is deployed (see [examples/site/README.md](../examples/site/README.md#deployment)).

## Nightly failures

`.github/workflows/interop.yml` runs every night on Chrome for Testing stable and beta. A stable
failure opens or comments on an `interop` issue; a beta failure shows only in the run. Failed
runs upload the logs and the final relying-party screenshot as an artifact. The exit code and
the last log line say which kind of failure it was:

| Exit | Log | Meaning |
|---|---|---|
| 0 | `OK` | Passed |
| 1 | `INTEROP FAILED` | The flow ran and went wrong: suspect the library, the example or Chrome |
| 2 | `PROVIDER UNAVAILABLE` | The preflight checks or a `/me` read failed: suspect the deployed provider |

## Running locally

Install uv and Chrome (the test turns on the EVP feature itself), then from the repository root:

```fish
uv sync --locked --all-packages --group interop
uv run --no-sync python interop/chrome_evp.py
```

`CHROME` picks another binary, `INTEROP_HEADFUL=1` shows the browser, and `INTEROP_OUT` keeps the
logs and screenshot in a directory of your choice:

```fish
env CHROME=/path/to/chrome INTEROP_HEADFUL=1 INTEROP_OUT=/tmp/pyevp-interop \
    uv run --no-sync python interop/chrome_evp.py
```

Ports 8001 and 9333 (DevTools) must be free. No issuer key or tunnel is needed.

A self-check with fake HTTP, DNS and DevTools responses runs without Chrome or the network:

```fish
uv run --no-sync python -m pytest interop/test_chrome_evp.py
```

## Chrome's consent prompt

Before the first issuance for an address, Chrome asks "verify this email automatically?" in
browser UI that DevTools cannot click. The profile therefore starts with the answer Chrome saves
after acceptance, `autofill.email_verification_state` in `Default/Preferences`. Its
`issuer_site` is the issuer origin, `https://mail.pyevp.dev`, not the site
`https://pyevp.dev`. Signing in through the provider's form is enough for Chrome's FedCM login
status.
