# Testing your application

{mod}`pyevp.testing` lets your test suite produce real, correctly signed tokens without a browser,
DNS or network access.

```python
from pyevp import SessionNonces
from pyevp.testing import FakeBrowser, FakeIssuer, make_verifier

issuer = FakeIssuer()  # https://issuer.example, for @example.com
browser = FakeBrowser(clock=issuer.clock)
verifier = make_verifier(issuer, audience="http://testserver")

nonces = SessionNonces({})  # a dict stands in for the session
token = browser.present(
    issuer.issue("alice@example.com", browser.public_jwk),
    audience="http://testserver",
    nonce=nonces.issue(),
)
result = verifier.verify_submission(token, nonces=nonces, email="alice@example.com")
```

- {class}`~pyevp.testing.FakeIssuer` serves DNS records, metadata and keys to
  {func}`~pyevp.testing.make_verifier` / {func}`~pyevp.testing.make_async_verifier`. You can override
  claims and headers (`claims={"email_verified": False}`) and rotate keys. To mimic Gmail's
  deviations from the draft, use {meth}`FakeIssuer.gmail_like() <pyevp.testing.FakeIssuer.gmail_like>`.
- {class}`~pyevp.testing.FixedClock` controls time for freshness tests.
- To test your handlers, inject the verifier through your framework's dependency mechanism,
  e.g. `app.dependency_overrides` in FastAPI or `monkeypatch` in Django. The examples' tests show
  both.

To drive the verification core without a verifier, for example when writing your own driver, see
{func}`pyevp.core.verification_steps`.

## Testing an issuer

{meth}`~pyevp.testing.FakeBrowser.issuance_request` signs a request as Chrome does, and
`FakeBrowser.present()` turns the EVT from the reply into the token a relying
party receives. Give the browser the {class}`~pyevp.testing.FixedClock` your
{class}`~pyevp.issuer.Issuer` was built with (`clock=`), so that the request is fresh:

```python
browser = FakeBrowser(clock=clock)
request = browser.issuance_request("alice@example.com", endpoint=ISSUANCE_ENDPOINT)
response = my_issuer.issuance_response(**request, user_emails=["alice@example.com"])
evt = json.loads(response.body)["issuance_token"]
token = browser.present(evt, audience="https://rp.example", nonce="n-1")
```

To test your endpoint instead, post `request["headers"]` and `request["body"]` to it.
