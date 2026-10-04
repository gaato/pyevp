# API reference

## `pyevp`

Everything most applications need is importable from the top-level package.

```{eval-rst}
.. automodule:: pyevp
   :members:
   :imported-members:

.. data:: DEFAULT_PROFILE
   :type: Profile

   The profile verifiers use unless told otherwise: ``compat-2026-10``.

.. data:: PROFILES
   :module: pyevp.profile
   :type: Mapping[str, Profile]

   All presets by name; see :meth:`Profile.named`.

.. autodata:: pyevp.Clock

.. autodata:: pyevp.Observer
```

## Verification core

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

.. data:: UserEmails

   The addresses whose mail the signed-in user receives, or a function returning them, which
   is called at most once and only for a request that is otherwise valid.  Empty when nobody
   is signed in.  Return ASCII addresses with A-label domains: they are compared with the
   requested address case-insensitively, and addresses the issuer could not issue for are
   ignored.

.. data:: AsyncUserEmails

   Like :data:`UserEmails`; the function may also be ``async``.

.. data:: RequestBody

   The request body, or a function reading at most ``n`` bytes of it, such as Django's
   ``request.read``.  The issuer reads only for a ``POST`` whose ``Content-Length`` allows
   it, and then no more than :data:`MAX_REQUEST_BODY` and one byte.

.. data:: AsyncRequestBody

   Like :data:`RequestBody`; it may also be read asynchronously, or be an asynchronous
   iterable of chunks such as Starlette's ``request.stream()``.

.. data:: IssuanceObserver

   Called with one :class:`IssuanceEvent` per request.  It must not block; what it raises is
   logged and ignored.

.. data:: MAX_REQUEST_BODY
   :value: 16384

   The largest issuance request body accepted, in bytes.  Larger requests are refused before
   their signature is checked.

.. data:: DEFAULT_ISSUANCE_PROFILE
   :type: IssuanceProfile

   The profile issuers use unless told otherwise: ``chrome-153``, what Chrome sends and
   accepts.

.. data:: METADATA_PATH
   :value: "/.well-known/email-verification"

   Where an issuer serves its metadata, relative to its identifier.

.. data:: WEB_IDENTITY_PATH
   :value: "/.well-known/web-identity"

   Where Chrome reads :func:`web_identity_document`, on the issuer's registrable domain.

.. data:: FEDCM_FETCH_DEST
   :value: "webidentity"

   The ``Sec-Fetch-Dest`` of Chrome's accounts request.
```

## Testing

```{eval-rst}
.. automodule:: pyevp.testing
```
