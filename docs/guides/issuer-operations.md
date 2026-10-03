# Running an issuer

```{warning}
`pyevp.issuer` follows draft-hardt-email-verification-02 and the request format Chrome sends from
version 153 on. It was tested end to end with Chrome 154.0.8037.92 (the
`#email-verification-protocol` flag, or `--enable-features=EmailVerificationProtocol`), and a
nightly job runs the example issuer against current Chrome stable and beta
([`interop/`](https://github.com/gaato/pyevp/tree/main/interop)). Chrome and the draft are
still changing, so expect the `chrome-153` issuance profile to follow them.
```

`pyevp.issuer` provides building blocks for issuing EVTs for email domains you control. It does
not include an HTTP server or user accounts. You plug it into your web framework and your login
system. A complete FastAPI sketch lives in
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

`pyevp.issuer` covers steps 1–4 except "the logged-in user controls the address", which is
yours. Chrome also requires the FedCM documents described in [What Chrome requires beyond the
draft](#chrome-requirements).

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

## Handle a request

```python
from pyevp.issuer import IssuanceError

try:
    request = issuer.parse_request(method=method, headers=raw_header_pairs, body=body)
    if current_user(cookies) is None or not current_user(cookies).owns(request.email):
        raise IssuanceError.authentication_required()
    response = issuer.success_response(issuer.issue(request))
except IssuanceError as exc:
    response = exc.to_response()
# response.status, response.headers, response.body
```

`parse_request` checks the method, `Content-Type`, `Sec-Fetch-Dest`, `Content-Digest`, the
signature and its freshness, the JSON body and the address. It also checks that the address is
in one of `email_domains`. It does **not** authenticate the user. Pass headers as `(name,
value)` pairs where your framework offers them, so that repeated header lines are kept apart.
With an async replay guard, use `aparse_request`.

`request.email` is exactly what the browser sent. The EVT asserts that string, and relying
parties compare it with what the user typed. If your accounts treat addresses
case-insensitively, compare them that way in `owns`, but do not rewrite `request.email`. Compare
only ASCII addresses, as {func}`pyevp.issuer.is_valid_email` accepts them: lowercasing a
non-ASCII address can turn it into someone else's (`\u212aate@` with a KELVIN SIGN becomes
`kate@`).

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
or someone else is. Raise `IssuanceError.authentication_required()` in every one of these cases.
Its body is fixed, and `parse_request` uses it for addresses outside `email_domains` too. Keep
the work done on each path similar as well. For example, do not query a database only when the
address looks valid.

Error responses only ever carry a fixed description per code. The detailed reason is in the
exception message for your logs.

## Keys and rotation

- Every key has a `kid`, and every EVT names the key that signed it.
- To rotate, publish the next key before using it. Pass it in `published_keys=[...]` until
  relying parties' caches (minutes) have picked it up, and then make it the `signer`.
- Keep publishing the retired public key until no token it signed can still be presented.
  Relying parties accept EVTs for about five minutes, so a day is plenty.
- A key that is already kept as PEM, for example in an identity provider's certificate store,
  loads with `SigningKey.from_pem(pem, kid=...)`. Only Ed25519 and P-256 keys work.
- Keys that never leave a KMS or HSM implement {class}`pyevp.issuer.Signer`: `alg`, `kid`,
  `public_jwk`, and `sign(signing_input) -> bytes` in JWS encoding (raw `r || s` for ES256).

## Replay and rate limiting

A signed request is only accepted within 300 seconds of its `created` time. Within that window,
a captured request could be resent together with the cookies. Pass `replay_guard=` to refuse a
request the second time it is seen. The guard keys on the signed content rather than the
signature bytes, so re-encoding an ES256 signature does not get a request past it. Use a shared
store, as described in {doc}`replay`.

Rate-limit the issuance endpoint per IP address in front of the application. `observer=`
receives an {class}`pyevp.issuer.IssuanceEvent` for every accepted or rejected request
(including requests rejected as replays) and every issued token, for metrics and audit logs.

(chrome-requirements)=

## What Chrome requires beyond the draft

Chrome 154 does more than the draft describes. Without the following, it fetches the metadata
and then stops without telling the page why.

- **FedCM account check.** Before issuing, Chrome fetches
  `https://<registrable domain of the issuer>/.well-known/web-identity`. For an issuer on
  `accounts.example.com`, that is `https://example.com/.well-known/web-identity`. Serve
  `pyevp.issuer.web_identity_document(accounts_endpoint=..., login_url=...)` there, with no
  `provider_urls` member. `accounts_endpoint` must be on the issuer's origin. Chrome requests it
  with the issuer's cookies and `Sec-Fetch-Dest: webidentity`. Answer with
  `pyevp.issuer.accounts_document([...])` listing the signed-in user's addresses; the typed address
  must be one of them.
- **Login status.** Chrome skips issuers it knows the user is signed out of. Send
  `Set-Login: logged-in` on a page response after login (or call
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
`/.well-known/email-verification`, the JWKS at `/email-verification/jwks`, issuance at
`/email-verification/issuance`, the FedCM accounts endpoint at `/fedcm/accounts`, and
`/.well-known/web-identity`. The issuer's `issuance_endpoint` and `jwks_uri` must use these
paths. `IssuerSite` raises `ImproperlyConfigured` otherwise. To use other paths, set
`issuance_path`, `jwks_path` and the other `*_path` attributes in a subclass.

Subclass {class}`~pyevp.contrib.django.issuer.IssuerSite` to adapt it:

- `user_emails(request)` returns the addresses the signed-in user may get tokens for, following
  [Deciding who gets a token](#who-gets-a-token). It has no default, and `IssuerSite` raises
  `ImproperlyConfigured` until you override it: a user model's email field is only right if your
  sign-up flow verified it. Return, for example, the verified addresses of django-allauth, or
  what your mail system delivers to the user's mailbox.
- `owns(request, email)` compares the requested address with those, case-insensitively by
  default.
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
synchronous, so use the synchronous guard. Bodies over 16 KiB are refused before they are read.

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
{class}`~pyevp.contrib.django.issuer.WebIdentityView` there, or the document from
`web_identity_document()`.

## Not supported yet

- `private_email` / `directed_email` requests are answered with `private_email_not_supported`,
  and the metadata says `private_email_supported: false`.
- The pre-153 Chrome format (`application/x-www-form-urlencoded` with a `request_token`) is
  refused with 415.
