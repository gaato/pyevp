(django-issuer)=

# Django issuer

{mod}`pyevp.contrib.django.issuer` (`pip install "pyevp[django]"`) serves every issuer endpoint,
including the ones Chrome needs, from Django views. It is for Django projects that already sign
their users in. Read {doc}`issuer-operations` for the setup and {doc}`issuer-policy` for who
gets a token. A complete project lives in
[`examples/issuer_django`](https://github.com/gaato/pyevp/tree/main/examples/issuer_django).

```python
# urls.py on the issuer's origin
from pyevp.contrib.django.issuer import IssuerSite


class Site(IssuerSite):
    def user_emails(self, request):
        return delivered_to(request.user)  # your mail system's answer


evp = Site(issuer)  # a pyevp.issuer.Issuer
urlpatterns = [path("", include(evp.urls)), ...]
```

Include `evp.urls` at the root of the issuer's origin. It serves the metadata, issuance and the
JWKS where the issuer's configuration says, the FedCM accounts endpoint at `/fedcm/accounts`
(`accounts_path`), and `/.well-known/web-identity`.

Subclass {class}`~pyevp.contrib.django.issuer.IssuerSite` to adapt it:

- `user_emails(request)` returns the addresses the signed-in user may get tokens for. It has no
  default: a user model's email field is right only if your sign-up flow verified it. Return,
  for example, the verified addresses of django-allauth, or what your mail system delivers to
  the user's mailbox.
- `get_issuer(request)` returns the issuer for the request. Override it instead of passing an
  `Issuer` when one deployment serves several issuers, for example one per host.
- `login_url` (an argument) is where Chrome sends users who are not signed in. It defaults to
  `settings.LOGIN_URL`.

Each endpoint is also a view of its own, for mounting it elsewhere with the same hooks, such as
`AccountsView.as_view(site=evp)`. Pass `replay_guard=EVPReplayGuard()` (the sync one) to the
`Issuer`; no extra database alias is needed.

## Settings

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

{class}`~pyevp.contrib.django.issuer.LoginStatusMiddleware` tells Chrome about logins and
logouts without changes to your login views. `manage.py check --deploy` warns about the session
cookie (`pyevp.W001`, `pyevp.W002`). If your session middleware sets the cookie's attributes per
response instead, add both to `SILENCED_SYSTEM_CHECKS`.

## Adding it to an existing application

- Include `evp.urls` at the root, before the application's own patterns. Plugin systems that
  mount apps under a prefix cannot serve `/.well-known/`.
- Route `/.well-known/email-verification`, `/.well-known/web-identity`, the issuance and JWKS
  paths, and `/fedcm/` to Django in the reverse proxy. A proxy that hands unknown paths to a
  single-page app answers them with its HTML, and Chrome fails without an error.
- If the issuer is on a subdomain such as `accounts.example.com`, serve
  {class}`~pyevp.contrib.django.issuer.WebIdentityView` (or `web_identity_response()`) at
  `https://example.com/.well-known/web-identity`.
