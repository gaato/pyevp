# API reference

## `pyevp`

Everything most applications need is importable from the top-level package.

```{eval-rst}
.. automodule:: pyevp
   :members:
   :imported-members:

.. data:: pyevp.DEFAULT_PROFILE
   :type: Profile

   The profile verifiers use unless told otherwise: ``compat-2026-10``.

.. data:: pyevp.profile.PROFILES
   :type: Mapping[str, Profile]

   All presets by name; see :meth:`Profile.named`.

.. autodata:: pyevp.Clock

.. autodata:: pyevp.Observer
```

## Verification core

These low-level modules may change in any minor release before 1.0 (see the
{doc}`compatibility`).

```{eval-rst}
.. automodule:: pyevp.core
   :members: verification_steps, ResolveTxt, FetchJson, MarkUsed, Effect, Steps, replay_key

.. automodule:: pyevp.token
   :members: parse_token, ParsedToken, CompactJWT, compute_sd_hash, build_kb, sign_jwt

.. automodule:: pyevp.discovery
```

## Diagnostics

```{eval-rst}
.. automodule:: pyevp.diagnostics
```

## Adapters

```{eval-rst}
.. automodule:: pyevp.adapters.dnspython

.. automodule:: pyevp.adapters.httpx

.. automodule:: pyevp.adapters.doh

.. automodule:: pyevp.adapters.urllib
   :exclude-members: CLOUDFLARE, GOOGLE, DnssecError, DohError, FetchError
```

## Integrations

```{eval-rst}
.. automodule:: pyevp.contrib.django

.. automodule:: pyevp.contrib.django.issuer
   :members: IssuerSite, MetadataView, JWKSView, IssuanceView, AccountsView, WebIdentityView,
      LoginStatusMiddleware
```

## Issuer

```{eval-rst}
.. automodule:: pyevp.issuer
   :members:
   :imported-members:
```

## Testing

```{eval-rst}
.. automodule:: pyevp.testing
```
