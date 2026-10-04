# For issuer operators

If you run an email service and issue EVP tokens, you can check what relying parties using this
library will see. To build an issuer with this library, see {doc}`issuer-operations`.

```sh
uvx --from "pyevp[cli]" pyevp discover your-domain.example
uvx --from "pyevp[cli]" pyevp discover your-domain.example --profile draft-hardt-02 --json
```

`discover` reports problems such as:

- a missing `_email-verification` TXT record, or more than one `iss=` record;
- metadata whose `issuer` does not exactly match the delegated `https://<host>`;
- a `jwks_uri` that is not HTTPS;
- signing algorithms the profile does not accept;
- no key able to verify the advertised algorithms;
- keys without `kid` when the profile requires one.

The same checks are available in code, for example from a monitoring job:

```python
from pyevp.diagnostics import discover

report = discover("your-domain.example", resolver=..., fetcher=...)
assert report.ok, report.problems
```

To test token issuance end to end, combine your issuer with {class}`pyevp.testing.FakeBrowser`. It
holds a key-binding key, signs issuance requests the way Chrome does
(`FakeBrowser.issuance_request`, whose result goes into `Issuer.issuance_response`), and builds
the presentation token from your EVT.
