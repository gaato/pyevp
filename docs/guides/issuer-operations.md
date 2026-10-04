# Running an issuer

```{warning}
`pyevp.issuer` follows draft-hardt-email-verification-02 and the request format of Chrome 153
and later. Both are still changing, and `pyevp.issuer` will change with them.
```

This guide is for mail hosts and identity providers that want to give their users EVTs for
the addresses they control. `pyevp.issuer` answers every endpoint of an issuer as
framework-neutral responses. Your framework routes requests to it, and your login system says
which addresses the signed-in user controls. Deciding that is the hard part; read
{doc}`issuer-policy` before going live. Django projects can use {doc}`issuer-django`. A complete
FastAPI issuer lives in
[`examples/issuer_fastapi`](https://github.com/gaato/pyevp/tree/main/examples/issuer_fastapi).

## What an issuer does

1. Each email domain delegates to the issuer with a DNS record,
   `_email-verification.<domain> TXT "iss=<issuer host>"`.
2. The issuer serves a metadata document at `https://<issuer host>/.well-known/email-verification`
   and its public keys at `jwks_uri`.
3. The browser sends a signed `POST` to the issuance endpoint, with the issuer's session cookies.
   If the signed-in user controls the requested address, the issuer returns an EVT bound to the
   browser's key.

Relying parties may accept tokens only from issuers they list (`allowed_issuers`, for example
`["https://accounts.example.com"]`). Your issuer identifier is what they list, so keep it stable.

## Before you start

- An HTTPS host for the issuer. Its identifier is `https://<host>`.
- Control of DNS for every email domain, to publish its TXT record.
- A session cookie set with `SameSite=None; Secure`, because Chrome's requests to the issuer are
  cross-site.
- Control of `/.well-known/web-identity` on the issuer's registrable domain (`example.com` for
  `accounts.example.com`). Chrome reads only that one document per registrable domain, so each
  site can have only one issuer. A hosting platform or identity provider serving many
  customers runs one issuer for all their domains, not one per tenant subdomain.

## Set up

Generate a signing key and keep the private JWK in your secret store:

```sh
pyevp issuer keygen --kid 2026-10 --alg ES256 --out signing-key.json
```

```python
from pyevp.issuer import Issuer, SigningKey

issuer = Issuer(
    issuer="https://accounts.example.com",
    issuance_endpoint="https://accounts.example.com/email-verification/issuance",
    jwks_uri="https://accounts.example.com/email-verification/jwks",
    signer=SigningKey.from_jwk(load_secret("evp-signing-key")),
    email_domains=["example.com"],
)
```

When the domains change at runtime, pass a function returning them instead of a list, such as
`lambda: Domain.objects.filter(enabled=True).values_list("name", flat=True)`.

`issuance_endpoint` must be the exact public URL. The issuer works behind a reverse proxy.

Print the documents and DNS records to publish, then check them as relying parties will see
them:

```sh
pyevp issuer documents --issuer https://accounts.example.com \
    --issuance-endpoint https://accounts.example.com/email-verification/issuance \
    --jwks-uri https://accounts.example.com/email-verification/jwks \
    --key signing-key.json --domain example.com
pyevp discover example.com --profile draft-hardt-02
```

## Serve the endpoints

Each endpoint is one call returning an {class}`~pyevp.issuer.IssuerResponse`, whose status,
headers and body you send as they are:

| Path | Call |
|---|---|
| `issuer.issuance_path` | `issuer.issuance_response(method=..., headers=..., body=..., user_emails=...)`, or `await issuer.aissuance_response(...)` |
| `METADATA_PATH` | `issuer.metadata_response()` |
| `issuer.jwks_path` | `issuer.jwks_response()` |
| an accounts path of your choice | `issuer.accounts_response(headers=..., user_emails=...)` |
| `WEB_IDENTITY_PATH`, on the registrable domain | `web_identity_response(accounts_endpoint=..., login_url=...)` |

```python
async def issuance(request):  # every method of issuer.issuance_path
    response = await issuer.aissuance_response(
        method=request.method,
        headers=request.headers.items(),
        body=request.stream(),
        user_emails=lambda: addresses_of(current_user(request)),  # [] when nobody is
    )
    return Response(response.body, status=response.status, headers=response.headers)
```

`user_emails` is consulted only for an otherwise valid request. Every refusal is an EVP
response; nothing is raised.

- **Methods.** Route every method, so that a `GET` gets an EVP error.
- **Headers.** Pass `(name, value)` pairs if the framework has them; joined headers work too.
- **Body.** Pass a reader (`request.read`, or `request.stream()` for `aissuance_response`), or
  bytes.
- **Addresses.** Pass a collection or a function returning one (async with `aissuance_response`).
  Return ASCII addresses with A-label domains.
- **Replay guard.** An async one needs `aissuance_response`.

(chrome-requirements)=

## What Chrome requires beyond the draft

Without these, Chrome fetches the metadata and then stops without telling the page why.

- **Web identity.** Serve `web_identity_response(accounts_endpoint=..., login_url=...)` at
  `https://<registrable domain>/.well-known/web-identity`. `accounts_endpoint` must be on the
  issuer's origin.
- **Accounts.** Answer the accounts endpoint with `issuer.accounts_response(...)`. Chrome
  issues only for an address it lists.
- **Login status.** Send `login_status_headers(signed_in=True)` (`Set-Login: logged-in`) on a
  page response after login, and `signed_in=False` after logout, or call
  `navigator.login.setStatus(...)`. A single-page app that logs out through an API call or an
  OpenID Connect redirect must call `navigator.login.setStatus("logged-out")` itself.
- **Cookies.** Scope the `SameSite=None; Secure` session cookie to the issuer's origin. It is
  then sent with cross-site form posts too, so protect login, logout and every other request
  that changes the session against CSRF (a token, or checking `Sec-Fetch-Site` or `Origin`), in
  the whole application that shares the session.
- **Signing algorithm.** Chrome accepts only `EdDSA`, `ES256` and `RS256` in the EVT header.
  For Ed25519 keys, the default `chrome-153` profile writes `EdDSA`, which strict
  (`draft-hardt-02`) relying parties refuse. Use an ES256 key to satisfy both default and strict
  relying parties.

## Check your deployment

**Discovery.** `pyevp discover <domain>` checks the TXT record, the metadata and the keys the way
a relying party does; add `--profile draft-hardt-02` for the strict profile. Monitoring jobs can
call {func}`pyevp.diagnostics.discover`.

**Tests.** {class}`pyevp.testing.FakeBrowser` signs issuance requests the way Chrome does and
presents the EVT you return, so a test can run the whole flow against your issuer; see
{doc}`testing`.

**Chrome.** Start Chrome with `--enable-features=EmailVerificationProtocol` (or turn on
`chrome://flags/#email-verification-protocol`), sign in to the issuer, and verify an address on a
relying party. If Chrome sends no token, recheck the list above.
