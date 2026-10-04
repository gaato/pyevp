# Command line

The `pyevp` command is for relying-party developers and operators, and for issuer operators
setting up and checking their issuer. It needs the `cli` extra. You can run it without
installing anything into your project:

```sh
uvx --from "pyevp[cli]" pyevp --help
```

## `pyevp discover`

Check a domain's issuer the way a relying party sees it: the DNS record, the metadata, the keys,
and whether they work under a profile.

```sh
pyevp discover gmail.com
pyevp discover alice@example.com --profile draft-hardt-02
pyevp discover example.com --doh            # resolve over DNS-over-HTTPS
```

## `pyevp inspect`

Decode a token offline. It shows the headers, the claims, how long ago each part was issued,
whether `sd_hash` matches and the holder key thumbprint. **Signatures are not verified.**

```sh
pbpaste | pyevp inspect
pyevp inspect "$TOKEN" --json
```

## `pyevp verify`

Run the full verification, as your server would:

```sh
pyevp verify "$TOKEN" --audience https://example.com --nonce "$NONCE" --email alice@example.com
```

## `pyevp issuer`

Set up an issuer for your own email domains (see {doc}`issuer-operations`).
`keygen` writes the private JWK to a new file readable only by you, and prints the public one.
`documents` prints the metadata, the JWKS and the DNS records to publish.

```sh
pyevp issuer keygen --kid 2026-10 --alg ES256 --out signing-key.json
pyevp issuer documents --issuer https://accounts.example.com \
    --issuance-endpoint https://accounts.example.com/email-verification/issuance \
    --jwks-uri https://accounts.example.com/email-verification/jwks \
    --key signing-key.json --domain example.com --publish next-key.json
```

`--domain` and `--publish` (a next or retired key's JWK file) can be repeated.

## Output and exit status

`discover`, `inspect` and `verify` accept `--json` for scripts; the `issuer` commands always
print JSON.

| Status | Meaning |
|---|---|
| 0 | success |
| 1 | verification failed, or discovery found problems |
| 2 | usage error |
| 3 | the `cli` extra is not installed |

```{note}
Tokens contain email addresses. Treat them as personal data, and avoid pasting real users'
tokens into shared terminals or issue trackers.
```
