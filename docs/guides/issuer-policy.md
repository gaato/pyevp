# Issuer policy

This page is for issuer operators deciding who gets tokens and keeping the issuer safe. Setting
it up is covered in {doc}`issuer-operations`.

(who-gets-a-token)=

## Deciding who gets a token

An EVT tells any relying party that the signed-in user controls the address, so it must prove
no more than a verification email would. The rule that holds up is **issue for an address only
if mail sent to it reaches this user**. Derive that from your mail system's delivery logic, not
from your account model or from what the user may send as. It is easy to get subtly wrong:

- **Aliases and forwards.** Follow aliases the way the MTA expands them, nested aliases and
  domain aliases included. An address the user forwards elsewhere without keeping a copy does
  not reach them. An address whose expansion loops is delivered to nobody.
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
  the user, and nothing for administrators just because their account has an email field. A
  long-lived "remember me" session keeps getting tokens for as long as it lasts.

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

The draft requires the same response whether the address does not exist, nobody is signed in,
or someone else is. The issuer answers all of these, and addresses outside `email_domains`, with
the same `authentication_required` response. Keep the work done on each path similar as well:
look up the signed-in user's addresses, never the requested one.

Error responses carry only a fixed description per code; the reason is in the observer's
{attr}`~pyevp.issuer.IssuanceEvent.detail` and in `DEBUG` logs of the `pyevp` logger, without
the address.

## Keys and rotation

- Every key has a `kid`, and every EVT names the key that signed it.
- To rotate, generate the next key and pass its public JWK in `published_keys=[...]`. Wait an
  hour, then make it the `signer`.
- Keep the retired public key in `published_keys` for a day, until no token it signed can still be
  presented.
- A PEM key, for example from an identity provider's certificate store, loads with
  `SigningKey.from_pem(pem, kid=...)`. Only Ed25519 and P-256 keys work.
- For a key that never leaves a KMS or HSM, implement {class}`pyevp.issuer.Signer`.

## Replay and rate limiting

A signed request is accepted for up to five minutes, and within that time a captured request
could be sent again together with the cookies. Pass a shared `replay_guard=` to refuse it the
second time; see {doc}`replay`.

Rate-limit the issuance endpoint per IP address in front of the application. `observer=`
receives one {class}`~pyevp.issuer.IssuanceEvent` per request, for metrics and audit logs.
