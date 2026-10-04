# Security policy

## Supported versions

Security fixes are made for the latest minor release only.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/gaato/pyevp/security/advisories/new).
Do not open a public issue.

Include the affected version, a description of the issue and, if possible, a
token or test case that reproduces it. Do not include real users' tokens: they
contain email addresses. `pyevp.testing.FakeIssuer` can build reproducers.

You should receive an acknowledgement within a week.

## Scope

In scope are flaws that make `Verifier` / `AsyncVerifier` accept a token they
should reject, that let a token make the relying party contact hosts
other than the issuer delegated by DNS, or that make `pyevp.issuer` or the
Django `IssuerSite` issue a token it should not.

Weaknesses of the protocol itself should be reported upstream to the
[IETF draft](https://github.com/dickhardt/email-verification) or the
[WICG specification](https://github.com/WICG/email-verification).
