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

## Single-page apps

An API without server sessions, for example one that authenticates with JWTs, keeps the nonce in
a cookie. [`examples/fastapi_spa`](https://github.com/gaato/pyevp/tree/main/examples/fastapi_spa)
is such an API, with password recovery that skips the email. See {doc}`spa` and
{doc}`password-recovery`.

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

{mod}`pyevp.contrib.django` renders the hidden input with a template tag and verifies what the
form submitted with {func}`~pyevp.contrib.django.verify_request`. Add `"pyevp.contrib.django"`
to `INSTALLED_APPS` and enable the `request` context processor, then put the tag inside the
form:

```{literalinclude} ../../examples/django/templates/signup.html
:language: html+django
```

In the view, verify before rendering the form again:

```{literalinclude} ../../examples/django/views.py
:language: python
:start-at: "@cache"
```

- All tags on a page share one nonce, so a page may have several forms. The session keeps the
  nonces of the last few pages, so forms in other tabs work too.
- `verify_request` is {meth}`pyevp.Verifier.verify_submission` for the form's field: it returns
  `None` when the form carried no token, and leaves the session alone. Otherwise it uses up the
  token's nonce and raises {class}`~pyevp.EVPError` on failure.
- In async views, call `await aget_nonce(request)` before rendering, because Django refuses
  session access from async code, including from a template tag. Then verify with
  `await averify_request(request, verifier, email=...)` and an {class}`~pyevp.AsyncVerifier`.

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

## Django building blocks

{mod}`pyevp.contrib.django` (`pip install "pyevp[django]"`) provides the parts every Django
integration needs:

- {class}`~pyevp.contrib.django.EVPCache` shares issuer metadata and key sets between workers
  through Django's cache framework. It takes a `CACHES` alias and a key prefix,
  `EVPCache("evp", prefix="evp:")`, and hashes keys so that long URLs fit Memcached's key
  limit. An evicted entry is simply fetched again.
- {class}`~pyevp.contrib.django.EVPReplayGuard` remembers accepted tokens in a database
  table, not in the cache. Caches evict entries before their TTL when they fill up, which would
  let a still-valid token be accepted again; a table keeps every row until the token expires,
  and a duplicate insert fails on the primary key even across workers. Add the app and create
  the table:

  ```python
  INSTALLED_APPS = [..., "pyevp.contrib.django"]
  ```

  then run `manage.py migrate`. Database errors propagate, so verification fails closed.

  Each record is committed in its own transaction as soon as the token is accepted, so a
  rollback of the request cannot undo it. That is impossible inside a transaction on the same
  database, whether an atomic block or a manual one with autocommit off, so there the guard
  raises `RuntimeError` rather than write a record that a rollback could erase. With
  `ATOMIC_REQUESTS` or `AUTOCOMMIT=False`, give the guard a second alias for the same
  database; both are set per alias:

  ```python
  DATABASES["evp"] = {**DATABASES["default"], "ATOMIC_REQUESTS": False, "AUTOCOMMIT": True}
  replay_guard = EVPReplayGuard(using="evp")
  ```

  Django's `TestCase` transactions are exempt, so tests need no extra setup.

With {class}`~pyevp.AsyncVerifier`, use {class}`~pyevp.contrib.django.AsyncEVPCache` and
{class}`~pyevp.contrib.django.AsyncEVPReplayGuard`. They keep database access off the event
loop, where Django would raise `SynchronousOnlyOperation`.

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

## Other frameworks

Anything else works the same way: issue a nonce with {class}`~pyevp.SessionNonces` into any
session that has `get` and item assignment, render it with {func}`~pyevp.token_input`, and pass
the hidden `evt` field to {meth}`pyevp.Verifier.verify_submission` with a `SessionNonces` for
the same session. Create one `SessionNonces` per request. Without a server session, implement
{class}`~pyevp.NonceStore` over a cookie, as in {doc}`spa`. Use {class}`~pyevp.Verifier` in
synchronous code and {class}`~pyevp.AsyncVerifier` under asyncio, which also takes an
{class}`~pyevp.AsyncNonceStore`.
