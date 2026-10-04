# Running an issuer

```{warning}
`pyevp.issuer` follows draft-hardt-email-verification-02 and the request format Chrome sends from
version 153 on. Both are still changing, and `pyevp.issuer` will change with them.
```

`pyevp.issuer` issues EVTs for email domains you control. It answers every endpoint of the
issuer itself, as framework-neutral responses, but it does not include an HTTP server or user
accounts. Your web framework passes requests in and sends the responses back, and your login
system tells it which addresses the signed-in user controls. A complete FastAPI sketch lives in
[`examples/issuer_fastapi`](https://github.com/gaato/pyevp/tree/main/examples/issuer_fastapi).
Django projects can use the ready-made views described in [Django](#django-issuer).

## What an issuer does

1. Publishes `_email-verification.<domain> TXT "iss=<issuer host>"` for each email domain.
2. Serves a metadata document at `https://<issuer host>/.well-known/email-verification` and a
   JWKS at its `jwks_uri`.
3. Receives a `POST` from the browser at its `issuance_endpoint`. The request is signed with an
   HTTP Message Signature (RFC 9421) using a key the browser generated and sent in
   `Signature-Key: sig=hwk;…`, and it carries the issuer's own session cookies.
4. Checks that the logged-in user controls the requested address, then returns an EVT bound to
   the browser's key.

`pyevp.issuer` covers steps 1–4. What it needs from you is which addresses the logged-in user
controls; see [Deciding who gets a token](#who-gets-a-token). Chrome also requires the FedCM
endpoints described in [What Chrome requires beyond the draft](#chrome-requirements), which
`pyevp.issuer` answers too.

## Set up

Generate a signing key and keep the private JWK in your secret store:

```sh
pyevp issuer keygen --kid 2026-10 --out signing-key.json
```

```python
from pyevp.issuer import Issuer, SigningKey

issuer = Issuer(
    issuer="https://issuer.example",
    issuance_endpoint="https://accounts.issuer.example/email-verification/issuance",
    jwks_uri="https://accounts.issuer.example/email-verification/jwks",
    signer=SigningKey.from_jwk(load_secret("evp-signing-key")),
    email_domains=["example.com"],
)
```

When the domains change at runtime, as on a hosting platform where they live in a database,
pass a callable instead of a list. It is called for every request and for `dns_txt_records()`,
it may return nothing, and names that are not valid domains are skipped with a warning rather
than taking the issuer down.

```python
def hosted_domains():
    return Domain.objects.filter(enabled=True).values_list("name", flat=True)


issuer = Issuer(..., email_domains=hosted_domains)
```

`issuance_endpoint` must be the exact public URL. The request signature covers its authority and
path. They are compared with this configured value, never with the `Host` header, so the issuer
works behind a reverse proxy and a signature made for another server is rejected.

Print what to publish, then check it as relying parties will see it:

```sh
pyevp issuer documents --issuer https://issuer.example \
    --issuance-endpoint https://accounts.issuer.example/email-verification/issuance \
    --jwks-uri https://accounts.issuer.example/email-verification/jwks \
    --key signing-key.json --domain example.com
pyevp discover example.com --profile draft-hardt-02
```

## Serve the endpoints

Each endpoint is one call that returns an {class}`~pyevp.issuer.IssuerResponse`, with the
status, headers and body to send as they are:

| Endpoint | Call |
|---|---|
| `issuance_endpoint` | `issuer.issuance_response(method=..., headers=..., body=..., user_emails=...)`, or `await issuer.aissuance_response(...)` |
| `/.well-known/email-verification` | `issuer.metadata_response()` |
| `jwks_uri` | `issuer.jwks_response()` |
| FedCM accounts endpoint | `issuer.accounts_response(headers=..., user_emails=...)` |
| `/.well-known/web-identity` | `web_identity_response(accounts_endpoint=..., login_url=...)` |

```python
async def issuance(request):  # route every method here
    response = await issuer.aissuance_response(
        method=request.method,
        headers=request.headers.items(),
        body=request.stream(),  # read only as far as needed
        user_emails=lambda: addresses_of(current_user(request)),  # [] when nobody is
    )
    return Response(response.body, status=response.status, headers=response.headers)
```

The issuer checks the method, the body's size, `Content-Type`, `Sec-Fetch-Dest`,
`Content-Digest`, the signature and its freshness, the JSON body and the address, and that the
address is in one of `email_domains`. Only then does it ask `user_emails` for the signed-in
user's addresses, and it issues an EVT only if the requested address is one of them. Every
refusal is an EVP error response; nothing is raised.

The glue around it:

- **Methods.** Route every method of the issuance endpoint to the issuer, so that a `GET` gets
  an EVP error rather than the framework's own.
- **Headers.** Pass them as `(name, value)` pairs where your framework offers them, so that
  repeated header lines are kept apart. Frameworks that join them with commas work too.
- **Body.** Pass a function that reads it, such as Django's `request.read`, or for
  `aissuance_response` the request's stream, and the issuer reads only as much as it accepts
  (16 KiB). The body itself, as bytes, works too.
- **Addresses.** `user_emails` is a collection or a function returning one; a function is
  called at most once, and only for a request that is otherwise valid, so that unsigned junk
  never reaches your database. `aissuance_response` also takes an `async` function. Pass an
  empty collection when nobody is signed in.
- **Replay guard.** With an async replay guard, use `aissuance_response`.

The EVT asserts the address exactly as the browser sent it, and relying parties compare it with
what the user typed. The issuer compares it with your addresses case-insensitively, and only
ASCII ones, as {func}`pyevp.issuer.is_valid_email` accepts them: lowercasing a non-ASCII address
can turn it into someone else's (`\u212aate@` with a KELVIN SIGN becomes `kate@`). Return
addresses with A-label domains (`xn--bcher-kva.example`, not `bücher.example`).

(who-gets-a-token)=

## Deciding who gets a token

An EVT tells any relying party that the signed-in user controls the address, so it must prove
no more than a verification email would. The rule that holds up is **issue for an address only
if mail sent to it reaches this user**. Derive that from your mail system's delivery logic, not
from your account model or from what the user may send as. It is easy to get subtly wrong:

- **Aliases and forwards.** Follow aliases the way the MTA expands them, nested aliases and
  domain aliases included. An address the user forwards elsewhere without keeping a copy no
  longer reaches them. An address whose expansion loops is delivered to nobody.
- **Shared aliases.** Every recipient of `team@` reads its mail, so each of them may get a token
  for it, exactly as each could click a link sent there.
- **Catch-alls.** `*@example.com` cannot be listed in the FedCM accounts response, so Chrome
  never asks for those addresses. Leave them out.
- **Send-as permissions** (sender addresses, "send as" delegations) are about sending. They do
  not count.
- **Domain names.** EVP requests carry A-labels in lowercase. If your data can hold one domain
  under two spellings (`bücher.example` and `xn--bcher-kva.example`, or a domain alias named like
  another tenant's domain), whoever controls one spelling could claim the other's addresses.
  Compare canonical names, and refuse names that are ambiguous.
- **Accounts.** Nothing for disabled accounts or disabled domains, nothing for a session that is
  halfway through two-factor authentication, nothing for an administrator who is impersonating
  the user, and nothing for administrators just because their account has an email field.

(identity-provider)=

### An identity provider as the issuer

A company can point its domain's TXT record at its identity provider, so that employees get
tokens for their work address. An identity provider knows who is signed in, but usually not
whether an account's email address was ever verified: administrators type addresses in,
directory and social-login sources sync them, and self-service enrollment lets users choose
them. Before issuing:

- Issue only for the company's own domains, and only to employee accounts, not to guests or
  external users.
- Refuse an address that more than one account carries. A social login or a second directory
  can bring in another account with the same address.
- Let administrators restrict issuance with the provider's own access policies, for example "is
  in the employees group". That is where the decision "this address really belongs to this
  person" is made.
- Consider requiring that the session was established with multi-factor authentication. A token
  lets other sites sign the user in, so it is worth no less than the login that produced it.
  Count a second factor only after a first one: a one-time code on its own, or a passkey that did
  not verify the user, is a single factor.
- Know every way an address can change: self-service profile edits, enrollment and invitation
  flows that let users type an address, and synchronisation from sources. Each one lets
  somebody claim an address nobody else has yet, such as `security@` or a former employee's.

## Preventing account enumeration

The draft requires the same response whether the address does not exist, nobody is logged in,
or someone else is. The issuer answers all of these, and addresses outside `email_domains`, with
the same `authentication_required` response. Keep the work done on each path similar as well:
look up the signed-in user's addresses, never the requested one.

Error responses only ever carry a fixed description per code. The detailed reason is in the
observer's {attr}`~pyevp.issuer.IssuanceEvent.detail` and in a `DEBUG` message on the `pyevp`
logger, neither of which contains the address.

## Keys and rotation

- Every key has a `kid`, and every EVT names the key that signed it.
- To rotate, publish the next key before using it. Pass it in `published_keys=[...]` until
  relying parties' caches have picked it up, and then make it the `signer`. The metadata and
  JWKS responses may be cached for five minutes (`Cache-Control: public, max-age=300`), and
  relying parties cache keys themselves for some minutes on top of that (this library: ten), so
  an hour is a safe wait.
- Keep publishing the retired public key until no token it signed can still be presented.
  Relying parties accept EVTs for about five minutes, so a day is plenty.
- A key that is already kept as PEM, for example in an identity provider's certificate store,
  loads with `SigningKey.from_pem(pem, kid=...)`. Only Ed25519 and P-256 keys work.
- Keys that never leave a KMS or HSM implement {class}`pyevp.issuer.Signer`: `alg`, `kid`,
  `public_jwk`, and `sign(signing_input) -> bytes` in JWS encoding (raw `r || s` for ES256).

## Replay and rate limiting

A signed request is only accepted within 300 seconds of its `created` time, or until its
`expires` if that is earlier. Within that window, a captured request could be resent together
with the cookies. Pass `replay_guard=` to refuse a request the second time it is seen. The guard
keys on the signed content rather than the signature bytes, so re-encoding an ES256 signature
does not get a request past it. It records only requests from users who control the address, so
nobody can fill the store without signing in, and a request refused before sign-in still works
after it. Use a shared store, as described in {doc}`replay`.

Rate-limit the issuance endpoint per IP address in front of the application. `observer=`
receives one {class}`pyevp.issuer.IssuanceEvent` per request, for metrics and audit logs. Its
`stage` says where the request ended: `"request"` (refused by validation, including replays),
`"ownership"` (the user does not control the address) or `"issue"` (an EVT was signed).

(chrome-requirements)=

## What Chrome requires beyond the draft

Chrome 154 does more than the draft describes. Without the following, it fetches the metadata
and then stops without telling the page why.

- **FedCM account check.** Before issuing, Chrome fetches
  `https://<registrable domain of the issuer>/.well-known/web-identity`. For an issuer on
  `accounts.example.com`, that is `https://example.com/.well-known/web-identity`. Serve
  `pyevp.issuer.web_identity_response(accounts_endpoint=..., login_url=...)` there; the document
  has no `provider_urls` member, which would make Chrome ignore it. `accounts_endpoint` must be
  on the issuer's origin. Chrome requests it with the issuer's cookies and `Sec-Fetch-Dest:
  webidentity`. Answer with `issuer.accounts_response(headers=..., user_emails=...)`, which
  lists the signed-in user's addresses that the issuer would issue for; the typed address must
  be one of them.
- **Login status.** Chrome skips issuers it knows the user is signed out of. Send
  `Set-Login: logged-in` (`pyevp.issuer.login_status_headers(signed_in=True)`) on a page
  response after login (or call
  `navigator.login.setStatus("logged-in")`), and `logged-out` on logout. A single-page app that
  logs out through an API call or an OpenID Connect logout redirect may never serve a page
  response from the issuer's origin; call `navigator.login.setStatus("logged-out")` from the app
  then.
- **Cookies.** Both the accounts request and the issuance request are cross-site from the relying
  party, so the session cookie needs `SameSite=None; Secure`. Scope it to the issuer's origin.
  Browsers then send it with cross-site form posts as well, so protect login, logout and other
  requests that change the session against CSRF (a CSRF token, or checking `Sec-Fetch-Site` /
  `Origin`). Otherwise another site can sign visitors in to an account it controls. When the
  issuer shares its session with an existing application, this applies to the whole
  application. Also keep in mind that a long-lived "remember me" session keeps getting tokens
  for as long as it lasts.
- **EVT header.** Chrome accepts only `EdDSA`, `ES256` and `RS256` in the EVT header, not the
  `Ed25519` the draft requires. The default `chrome-153` profile therefore writes `EdDSA` for
  Ed25519 keys, as Gmail does. Relying parties using this library's default profile accept
  that, and the strict `draft-hardt-02` verifier profile does not. With an ES256 key, both are
  satisfied.

Chrome also shows the user a one-time prompt per address ("verify this email automatically?")
before the first issuance. It starts the check when focus moves from the email field to another
form field, and it rate-limits repeated failures per address.

These requirements come from testing end to end with Chrome 154.0.8037.92, with the
`#email-verification-protocol` flag or `--enable-features=EmailVerificationProtocol`. A nightly
job runs the example issuer against current Chrome stable and beta
([`interop/`](https://github.com/gaato/pyevp/tree/main/interop)), so changes in Chrome show up
there.

(django-issuer)=

## Django

{mod}`pyevp.contrib.django.issuer` (`pip install "pyevp[django]"`) serves every endpoint above,
and the FedCM ones Chrome needs, from Django views. The signed-in Django user decides which
addresses get tokens. A complete project lives in
[`examples/issuer_django`](https://github.com/gaato/pyevp/tree/main/examples/issuer_django).

```python
# urls.py on the issuer's origin
from pyevp.contrib.django.issuer import IssuerSite


class Site(IssuerSite):
    def user_emails(self, request):
        return delivered_to(request.user)  # your mail system's answer


evp = Site(issuer)  # the Issuer from "Set up"
urlpatterns = [path("", include(evp.urls)), ...]
```

Include `evp.urls` at the root of the issuer's origin. It serves the metadata at
`/.well-known/email-verification`, issuance and the JWKS where the issuer's
`issuance_endpoint` and `jwks_uri` say, the FedCM accounts endpoint at `/fedcm/accounts`
(`accounts_path`), and `/.well-known/web-identity`.

Subclass {class}`~pyevp.contrib.django.issuer.IssuerSite` to adapt it:

- `user_emails(request)` returns the addresses the signed-in user may get tokens for, following
  [Deciding who gets a token](#who-gets-a-token). It has no default, and `IssuerSite` raises
  `ImproperlyConfigured` until you override it: a user model's email field is only right if your
  sign-up flow verified it. Return, for example, the verified addresses of django-allauth, or
  what your mail system delivers to the user's mailbox.
- `get_issuer(request)` returns the issuer for the request. Override it instead of passing an
  `Issuer` when one deployment serves several issuers, for example one per host.
- `login_url` (an argument) is where Chrome sends users who are not signed in. It defaults to
  `settings.LOGIN_URL`.

Each endpoint is also a view of its own, for mounting it somewhere else while keeping the same
hooks, such as `AccountsView.as_view(site=evp)`.
{class}`~pyevp.contrib.django.issuer.IssuanceView` is always exempt from CSRF checks and from
`ATOMIC_REQUESTS`. A forged cross-site request cannot carry `Sec-Fetch-Dest:
email-verification` or a valid signature. The exemption from `ATOMIC_REQUESTS` lets
{class}`~pyevp.contrib.django.EVPReplayGuard` commit its record on its own, so pass
`replay_guard=EVPReplayGuard()` to the `Issuer` without a second database alias. The view is
synchronous, so use the synchronous guard; `IssuerSite` raises `ImproperlyConfigured` for an
asynchronous one. It answers every method, and reads no more of a body than the issuer
accepts.

Settings:

```python
INSTALLED_APPS = [..., "pyevp.contrib.django"]  # replay guard table and system checks
MIDDLEWARE = [
    ...,
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "pyevp.contrib.django.issuer.LoginStatusMiddleware",
]
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True
```

{class}`~pyevp.contrib.django.issuer.LoginStatusMiddleware` adds `Set-Login: logged-in` or
`logged-out` to page responses, so Chrome learns about logins and logouts without changes to
your login views. With the app installed, `manage.py check --deploy` warns (`pyevp.W001`,
`pyevp.W002`) when the session cookie would not reach the issuer from Chrome's cross-site
requests. The check reads the settings. If your session middleware sets the cookie's attributes
per response instead, as some identity providers do, add both to `SILENCED_SYSTEM_CHECKS`.

Adding the issuer to an existing application usually means editing files the operator owns
rather than the application's code:

- Include `evp.urls` before the application's own patterns, at the root. Plugin systems that
  mount apps under a prefix cannot serve `/.well-known/`.
- Route `/.well-known/email-verification`, `/.well-known/web-identity`, `/email-verification/`
  and `/fedcm/` to Django in the reverse proxy. Configurations that hand every unknown path to a
  single-page app answer them with its HTML and a 200, which fails without an error.
- Set the session cookie, middleware and app as above.

If the issuer is on a subdomain such as `accounts.example.com`, Chrome reads
`/.well-known/web-identity` from `example.com`. Serve
{class}`~pyevp.contrib.django.issuer.WebIdentityView` there, or the response from
`web_identity_response()`.

## Not supported yet

- `private_email` / `directed_email` requests are answered with `private_email_not_supported`,
  and the metadata says `private_email_supported: false`.
- The pre-153 Chrome format (`application/x-www-form-urlencoded` with a `request_token`) is
  refused with 415.
