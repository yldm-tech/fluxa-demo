# spec — signing contract and known-answer vectors

| File | Purpose |
| --- | --- |
| [`SIGNING.md`](./SIGNING.md) | The signing contract: request signing, webhook verification, the encrypted envelope, and the event body |
| [`vectors.json`](./vectors.json) | Known-answer test vectors. **Do not hand-edit** |

## What `vectors.json` is

A set of (input → expected output) pairs generated from fluxa's **actual server-side signing
code**, not from a reading of the docs:

- `requests[]` — merchant API request signing. Given method / path / query / timestamp / body /
  secret, the expected `canonical` string and `signature`.
- `webhooks[]` — webhook verification. Given timestamp / body / secret, the expected `signature`.
- `envelopes[]` — the AES-256-GCM envelope. Given an envelope and secret, the expected decrypted
  `plaintext`. The fixture is produced with a fixed nonce for determinism and is verified to
  decrypt with the server's own decrypter.

Every language demo has a test that reproduces these **byte for byte**. That is the single
criterion for whether a port is correct — it needs no running server and does not depend on
anyone's interpretation of prose.

Edges covered: no query (the empty third canonical line), method-case normalization, empty body,
reordered query yielding an identical signature, repeated keys, non-ASCII body, empty webhook body.

### `get_query_utf16_divergence` — the one vector that discriminates

Every other vector uses an ASCII query, where **any** sort order — UTF-8 byte order, UTF-16,
even a culture-sensitive one — produces the same result. Only this vector separates a correct
implementation from one that merely looks correct:

```
raw_query = k=￿&k=😀           (U+FFFF vs U+1F600)
UTF-8 byte order → k=￿&k=😀     0xEF < 0xF0, so U+FFFF sorts first   ← what the server does
UTF-16 order     → k=😀&k=￿     0xFFFF > 0xD83D (the lead surrogate) — reversed
```

This is not theoretical. Mutation testing confirms it: swap the comparator in the Node
implementation for JavaScript's default `sort()` and **only this vector fails** — every other
vector, including the non-ASCII body one, still passes.

So each language must compare UTF-8 bytes explicitly:

| Language | Correct comparator |
| --- | --- |
| JavaScript | `Buffer.compare` (the default `sort()` is UTF-16) |
| Java | `Arrays.compareUnsigned` (`String.compareTo` is UTF-16) |
| C# | compare UTF-8 bytes (`Array.Sort` on strings is **culture-sensitive** — a real trap) |
| Python | `key=lambda s: s.encode("utf-8")` |
| PHP | `sort($a, SORT_STRING)` (`SORT_REGULAR` compares numeric-looking fragments numerically) |
| Ruby | `Array#sort` (already byte order) — but pass `-1` to `split` (see below) |
| Go / Rust | already byte order |

One more cross-language trap: `split` on `&` must **keep trailing empty fragments**. Ruby's
default `split` and Java's one-arg `String.split` drop them, which diverges from the server;
both need an explicit `-1` limit.

## Regenerating

`vectors.json` is generated and maintained inside the fluxa platform repository, where the
signing code lives — that is what makes it an independent oracle rather than a restatement of
this repo's own implementations. If the signing contract ever changes, the vectors are
regenerated there and updated here, and every language's test will fail loudly until its
implementation matches.

You do not need to regenerate anything to use this repo.
