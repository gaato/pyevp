# Testing your application

{mod}`pyevp.testing` lets your test suite produce real, correctly signed tokens without a browser,
DNS or network access.

```python
from pyevp.testing import FakeBrowser, FakeIssuer, make_async_verifier

issuer = FakeIssuer()  # https://issuer.example, for @example.com
browser = FakeBrowser(clock=issuer.clock)
verifier = make_async_verifier(issuer, audience="http://testserver")

token = browser.present(
    issuer.issue("alice@example.com", browser.public_jwk),
    audience="http://testserver",
    nonce=nonce_from_your_form,
)
```

To exercise {meth}`~pyevp.Verifier.verify_submission` without a web framework, a plain `dict`
stands in for the session: `nonces = SessionNonces({})`, then `nonce=nonces.issue()`.

- {class}`~pyevp.testing.FakeIssuer` serves DNS records, metadata and keys to
  {func}`~pyevp.testing.make_verifier` / {func}`~pyevp.testing.make_async_verifier`. You can override
  claims and headers (`claims={"email_verified": False}`) and rotate keys. To mimic Gmail's current
  deviations from the draft, use {meth}`FakeIssuer.gmail_like() <pyevp.testing.FakeIssuer.gmail_like>`.
- {class}`~pyevp.testing.FixedClock` controls time for freshness tests.
- To test your handlers, inject the verifier through your framework's dependency mechanism,
  e.g. `app.dependency_overrides` in FastAPI or `monkeypatch` in Django. The examples' tests show
  both.

The verification core can also be driven by hand. That is useful when writing your own driver:

```python
from pyevp.core import verification_steps

steps = verification_steps(token, audience=..., nonce=..., email=..., now=..., profile=...)
effect = next(steps)  # ResolveTxt("_email-verification.example.com")
effect = steps.send(["iss=issuer.example"])
...
```
