# Single-page apps and stateless APIs

The {doc}`quickstart <../quickstart>` keeps the nonce in a server session. An API that
authenticates with bearer tokens such as JWTs often has no session. This page shows where the
nonce goes instead, and what the browser side of a single-page app needs. The server code comes
from [`examples/fastapi_spa`](https://github.com/gaato/pyevp/tree/main/examples/fastapi_spa),
which has tests.

## Keeping the nonce in a cookie

Hand the nonce out from an endpoint and keep a copy in an HttpOnly cookie. A small
{class}`~pyevp.NonceStore` over the cookie lets
{meth}`~pyevp.AsyncVerifier.verify_submission` take it, as it would from a session:

```{literalinclude} ../../examples/fastapi_spa/app.py
:language: python
:start-after: "# nonce:start"
:end-before: "# nonce:end"
```

- The audience is the origin of the frontend, where the form is, not the origin of the API.
- As with a session, the nonce is used up only when a token arrived and presents it. The cookie
  holds one nonce, so a form opened in another tab replaces it.
- The cookie is client-side state, so enable {doc}`replay protection <replay>`. Otherwise a
  captured token can be sent again together with the old cookie.
- The frontend and the API must be on the same site, for example `app.example.com` and
  `api.example.com`. Otherwise the browser does not send a `SameSite=Strict` cookie.
- When they are on different origins, the frontend sends its requests with credentials
  (`fetch(url, {credentials: "include"})`, or `withCredentials: true` in axios), and the API
  allows them with CORS: name the frontend's origin and allow credentials.
- Over HTTPS the example names the cookie with the `__Host-` prefix, so that other hosts on the
  same site cannot plant a nonce. Keep that.

## In the browser

A sketch with React and TanStack Query, not tested itself:

```tsx
const nonce = useQuery({
  queryKey: ["evp-nonce"],
  queryFn: async () => {
    const response = await fetch(`${API}/api/evp/nonce`, { credentials: "include" })
    return (await response.json()).nonce as string
  },
  // Every request replaces the cookie: fetch once, again only after a token was used.
  staleTime: Infinity,
})

function onSubmit(event: React.FormEvent<HTMLFormElement>) {
  event.preventDefault()
  const form = new FormData(event.currentTarget)
  // POST {email: form.get("email"), evt: form.get("evt")} with credentials,
  // then refetch the nonce if a token was sent.
}

return (
  <form onSubmit={onSubmit}>
    <input type="email" name="email" autoComplete="email" />
    {nonce.data && (
      <input
        type="hidden"
        name="evt"
        autoComplete="email-verification-token"
        nonce={nonce.data}
      />
    )}
    <button type="submit">Continue</button>
  </form>
)
```

React 19 renders the `nonce` prop as a content attribute, which is what the browser reads.
Read the token in the submit handler, for example with `FormData` inside react-hook-form's
`handleSubmit`; sending it in a JSON body is fine.

Request the nonce once. A second request, from React's StrictMode or from refetching when the
window regains focus, replaces the cookie and leaves the page with a stale nonce;
`staleTime: Infinity` in TanStack Query avoids both. A form submitted before the nonce arrives
carries no token and falls back to your usual flow.

## Linting

Biome 2.5 reports `autocomplete="email-verification-token"` under
`lint/a11y/useValidAutocomplete`, because the value is not in the HTML standard yet. Suppress it
on the attribute:

```text
<input
  type="hidden"
  name="evt"
  // biome-ignore lint/a11y/useValidAutocomplete: EVP's token field is not in the HTML spec yet
  autoComplete="email-verification-token"
  nonce={nonce}
/>
```
