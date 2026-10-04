# DNS, HTTP and caching

Verification needs one DNS TXT lookup and two HTTPS GETs (metadata and keys). Both are pluggable
through {class}`~pyevp.TxtResolver` / {class}`~pyevp.JsonFetcher` and their async counterparts.
`Verifier.default()` picks the adapters below. Any constructor argument can be overridden:

```python
Verifier.default(audience=..., resolver=..., fetcher=..., cache=...)
```

## HTTP: httpx2 or httpx

{mod}`pyevp.adapters.httpx` works with [httpx2](https://github.com/pydantic/httpx2) (pydantic's
maintained fork) or httpx, and prefers httpx2 when both are installed. Install one of:

```sh
pip install "pyevp[dns,httpx2]"
pip install "pyevp[dns,httpx]"
```

A client from either library can be passed explicitly, for example to share connection pools
or set proxies: `HttpxFetcher(httpx2.Client(...))`. Redirects are never followed, even when the
client was configured to follow them. Responses are requested uncompressed, compressed ones
are refused, and bodies are size-capped.

## Private networks (SSRF)

The issuer host comes from a DNS record that anyone can publish for their own domain, and the
key set's location from that issuer's metadata. Without care, a crafted token could make your
server send requests into its own network. PyEVP guards against this in two places:

- Discovery refuses issuer hosts and metadata URLs that are IP literals, single-label names or
  special-use names (`localhost`, `.local`, `.home.arpa`, `.internal`).
- The fetchers resolve each host before connecting and refuse it unless every address is
  globally routable (no loopback, private, link-local or unique-local addresses).

The HTTP library resolves the name again when it connects, so a DNS server that answers
differently the second time (DNS rebinding) is not caught. If that matters to you, send the
requests through an egress proxy that enforces the policy itself.

Behind such a proxy, or to reach an issuer on a private network during development, turn the
address check off:

```python
HttpxFetcher(require_global_addresses=False)
UrllibFetcher(require_global_addresses=False)
```

`resolve_host=` replaces the resolver used for the check, for example with one that matches
your HTTP stack's.

## DNS: system resolver

{mod}`pyevp.adapters.dnspython` uses the system resolver configuration. With
`require_dnssec=True`, answers must carry the AD flag. That flag is only meaningful when you
trust a validating resolver, such as one on localhost.

## DNS over HTTPS

Where plain DNS is unavailable or untrusted, as on serverless platforms or in locked-down
networks, {mod}`pyevp.adapters.doh` resolves TXT records through a DoH JSON API using only the HTTP
client:

```python
from pyevp.adapters.doh import CLOUDFLARE, AsyncDohResolver

verifier = AsyncVerifier.default(audience=..., resolver=AsyncDohResolver())  # Google
verifier = AsyncVerifier.default(audience=..., resolver=AsyncDohResolver(CLOUDFLARE))
```

`require_dnssec=True` trusts the provider's AD flag. Unsigned zones such as gmail.com never pass
it. With `dnspython[doh]` installed, an RFC 8484 resolver can be used instead:

```python
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["https://cloudflare-dns.com/dns-query"]
DnsPythonResolver(resolver)
```

## Standard library only

{mod}`pyevp.adapters.urllib` needs nothing beyond PyEVP's core dependencies, for applications
that already chose an HTTP stack and do not want httpx or dnspython added. Without dnspython
there is no stdlib way to query TXT records, so it resolves them over DoH:

```python
from pyevp import Verifier
from pyevp.adapters.urllib import CLOUDFLARE, UrllibDohResolver, UrllibFetcher

verifier = Verifier(audience=..., resolver=UrllibDohResolver(), fetcher=UrllibFetcher())
verifier = Verifier(audience=..., resolver=UrllibDohResolver(CLOUDFLARE), fetcher=UrllibFetcher())
```

They behave like the httpx adapters: no redirects, no compressed responses, size-capped bodies.
The DoH trade-offs above apply: the provider sees which domains you look up, and
`require_dnssec=True` means trusting it. Both adapters are synchronous. Proxies from the
environment are honoured; pass `handlers` to configure proxies or TLS explicitly:

```python
UrllibFetcher(handlers=[urllib.request.HTTPSHandler(context=ssl_context)])
```

## Caching

Issuer metadata and key sets are cached for 10 minutes (`cache_ttl`) in a process-local
{class}`~pyevp.InMemoryCache`. Pass any {class}`~pyevp.Cache` implementation to share it between
workers; {class}`pyevp.contrib.django.EVPCache` is one backed by Django's cache.
{class}`~pyevp.AsyncVerifier` also accepts an {class}`~pyevp.AsyncCache`, whose methods are
coroutines, for stores that must not be called on the event loop. When a signature does not verify,
the keys are fetched again to pick up key rotation, at most once per `min_refresh_interval`
and URL, even when the fetch fails or verifications run concurrently.
