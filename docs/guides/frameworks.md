# Framework integration

The repository's `examples/` directory has a complete, tested project for each integration
below. Copy one out and replace `pyevp = { workspace = true }` with a normal dependency to start
your own.

## FastAPI

Create one {class}`~pyevp.AsyncVerifier` at startup and inject it as a dependency, so that tests can
override it. Starlette's `SessionMiddleware` keeps the session in a signed cookie, so the
example enables a replay guard.

```{literalinclude} ../../examples/fastapi/app.py
:language: python
:start-at: "@asynccontextmanager"
```

## Flask

Build the synchronous {class}`~pyevp.Verifier` in the application factory and keep it in
`app.extensions`, so that tests can pass one wired to fakes. Flask's default session is a signed
cookie, so the example enables a replay guard.

```{literalinclude} ../../examples/flask/app.py
:language: python
:start-at: "def create_app"
```

## fastapi-users

Register users through your own route. A valid token creates the user with
`is_verified=True`; otherwise the usual verification email applies. Build the `UserCreate` on
the server and pass `safe=False` only so that `is_verified` is kept.

```{literalinclude} ../../examples/fastapi_users/app.py
:language: python
:start-at: "@app.post(\"/register\""
:end-before: "@app.get(\"/me\""
```

## AuthX (passwordless login)

When the verified address *is* the login, replay protection is essential.

```{literalinclude} ../../examples/authx/app.py
:language: python
:start-at: "@app.post(\"/login\")"
```

## Django

{mod}`pyevp.contrib.django` (`pip install "pyevp[django]"`) renders the hidden input with a
template tag and verifies what the form submitted with
{func}`~pyevp.contrib.django.verify_request`, which works like
{meth}`~pyevp.Verifier.verify_submission`. Add `"pyevp.contrib.django"` to `INSTALLED_APPS`,
enable the `request` context processor, run `manage.py migrate`, and put the tag inside the
form:

```{literalinclude} ../../examples/django/templates/signup.html
:language: html+django
```

In the view, verify before rendering the form again:

```{literalinclude} ../../examples/django/views.py
:language: python
:start-at: "@cache"
```

In async views, call `await aget_nonce(request)` before rendering, because Django refuses
session access from async code, including from a template tag. Then verify with
`await averify_request(request, verifier, email=...)` and an {class}`~pyevp.AsyncVerifier`.

The app also provides storage that works across workers:

- {class}`~pyevp.contrib.django.EVPCache` keeps issuer metadata and key sets in Django's cache
  framework. It takes a `CACHES` alias and a key prefix: `EVPCache("evp", prefix="evp:")`.
- {class}`~pyevp.contrib.django.EVPReplayGuard` remembers accepted tokens in a database table.
  With `ATOMIC_REQUESTS` or `AUTOCOMMIT=False` it needs a second database alias; see
  {doc}`replay`.

With an {class}`~pyevp.AsyncVerifier`, use {class}`~pyevp.contrib.django.AsyncEVPCache` and
{class}`~pyevp.contrib.django.AsyncEVPReplayGuard`.

Combined with the {doc}`standard-library adapters <transport>`, a Django project needs no
dependency beyond PyEVP's core:

```python
from pyevp import Verifier
from pyevp.adapters.urllib import UrllibDohResolver, UrllibFetcher
from pyevp.contrib.django import EVPCache, EVPReplayGuard

verifier = Verifier(
    audience=settings.EVP_ORIGIN,
    resolver=UrllibDohResolver(),
    fetcher=UrllibFetcher(),
    cache=EVPCache(),
    replay_guard=EVPReplayGuard(),
)
```

## django-allauth

Override `DefaultAccountAdapter.is_email_verified`. A valid token makes the new `EmailAddress`
verified, so no confirmation mail is sent; anything else falls back to allauth's normal flow.

```{literalinclude} ../../examples/django_allauth/evp_allauth.py
:language: python
:start-at: "@cache"
```

Add `{% load pyevp %}` and `{% evp_token_input %}` to the signup form template. In the settings,
add `"pyevp.contrib.django"` to `INSTALLED_APPS` and set `ACCOUNT_ADAPTER`,
`ACCOUNT_FORMS["signup"]` and `EVP_ORIGIN` (see `examples/django_allauth/settings.py`).

## Other frameworks

Anything else works the same way: issue a nonce with {class}`~pyevp.SessionNonces` into any
session that has `get` and item assignment, render it with {func}`~pyevp.token_input`, and pass
the hidden `evt` field to {meth}`pyevp.Verifier.verify_submission` with a `SessionNonces` for
the same session. Create one `SessionNonces` per request. Use {class}`~pyevp.Verifier` in
synchronous code and {class}`~pyevp.AsyncVerifier` under asyncio, which also takes an
{class}`~pyevp.AsyncNonceStore`.

An API without server sessions, such as one that authenticates with JWTs, implements
{class}`~pyevp.NonceStore` over a cookie instead:
[`examples/fastapi_spa`](https://github.com/gaato/pyevp/tree/main/examples/fastapi_spa), described
in {doc}`spa` and {doc}`password-recovery`.
