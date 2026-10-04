# Replay protection

The nonce on the form is the first line of defence: store it server-side and consume it once.
Some setups cannot do that:

- **Client-side sessions** such as Starlette's signed-cookie `SessionMiddleware`. An attacker who
  captured a token can resend it with the old cookie, which still contains the nonce.
- **Nonces kept in a cookie** by APIs without a server session (see {doc}`spa`).
- **Concurrent requests** racing on the same session.

A replay guard remembers every accepted token until it would expire anyway, and rejects a
second use with `ErrorCode.TOKEN_REPLAYED`. Replay protection is off by default; enable it by
passing a guard:

```python
from pyevp import AsyncVerifier, InMemoryReplayGuard

verifier = AsyncVerifier.default(audience="https://example.com", replay_guard=InMemoryReplayGuard())
```

The guard is consulted only after every other check has passed, so rejected tokens never fill
the store. Errors raised by the guard itself, such as a store outage, propagate unchanged.

## Shared stores

{class}`~pyevp.InMemoryReplayGuard` only protects a single process. With several workers,
implement {class}`~pyevp.ReplayGuard` or {class}`~pyevp.AsyncReplayGuard` as an atomic "add if
absent":

```python
import math


class RedisReplayGuard:
    def __init__(self, redis):
        self.redis = redis

    def mark_used(self, key, expires_at):
        # Round up: the key must not disappear before the token expires.
        pxat = math.ceil(expires_at.timestamp() * 1000)
        return bool(self.redis.set(f"evp:used:{key}", 1, nx=True, pxat=pxat))
```

The store must keep each record until it expires. Do not build a guard on a cache that evicts
under memory pressure: once the record is evicted, the token is accepted again. For Redis this
means `maxmemory-policy noeviction` (the `volatile-*` policies evict exactly these keys, which
have a TTL), so that a full Redis rejects the write and verification fails instead.

## Django

{class}`~pyevp.contrib.django.EVPReplayGuard` (or {class}`~pyevp.contrib.django.AsyncEVPReplayGuard`
for an {class}`~pyevp.AsyncVerifier`) keeps records in a database table, which needs
`"pyevp.contrib.django"` in `INSTALLED_APPS` and `manage.py migrate`. Database errors
propagate, so verification fails closed.

Each record is committed in its own transaction, so a rollback of the request cannot undo it.
Inside a transaction on the same database, whether `ATOMIC_REQUESTS`, `transaction.atomic()` or
autocommit turned off, the guard raises `RuntimeError` instead. In that case give it a second
alias for the same database:

```python
DATABASES["evp"] = {**DATABASES["default"], "ATOMIC_REQUESTS": False, "AUTOCOMMIT": True}
replay_guard = EVPReplayGuard(using="evp")
```
