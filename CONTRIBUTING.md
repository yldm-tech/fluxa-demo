# Contributing

Thanks for taking a look. This repo holds working merchant integrations for the fluxa payment
API in 8 languages. The most useful contributions are usually: a fix for something that's wrong,
a clearer comment where you got stuck, or a port to a language that isn't here yet.

## The one hard rule

**Every language must reproduce `spec/vectors.json` byte for byte.**

Those are known-answer vectors generated from fluxa's actual server-side signing code. They are
the single criterion for whether an implementation is correct — no running server, no credentials,
no dependence on anyone's reading of the prose in `spec/SIGNING.md`.

```bash
./verify-all.sh          # all languages; Docker fills in for runtimes you don't have
./verify-all.sh node     # just one
```

If your change makes a vector fail, the change is wrong — not the vector. If you believe a vector
itself is wrong, say so in the issue rather than editing `spec/vectors.json`; it's generated, not
hand-written.

## Before you open a PR

- `./verify-all.sh` passes.
- New behavior has a test. Then **check the test has teeth**: break the thing on purpose and
  confirm the test fails. A suite that stays green when you delete the CANONICAL_QUERY line is
  asserting nothing. CI runs exactly this mutation check against the Node reference.
- Comments are in English and explain **why**, not what. The comments in this repo carry traps
  that cost real time to find (the empty third canonical line, UTF-8 vs UTF-16 sorting, the
  partial-refund dedupe key). Don't compress them into `// sign request`.
- No secrets. `.env` is gitignored; keep it that way.

## Adding a language

Copy the shape of an existing one — `node/` is the reference the others were written against.
You need:

| | |
| --- | --- |
| a signing/client module | canonical + sign + HTTP + webhook verify/decrypt |
| a config loader | reads the shared `../.env`; real env vars win over the file |
| a charge entrypoint | creates a charge, branches on `instruction.type`, reads the order back |
| a webhook receiver | verify → (decrypt) → dedupe → 2xx |
| a vectors test | every entry in `spec/vectors.json` |
| a README | how to run it, plus a Docker one-liner |

Then add a block to `verify-all.sh` matching its neighbours, and a row to both READMEs.

Keep dependencies minimal — most demos here are standard-library only. Someone reading this repo
is trying to understand a signature scheme, not evaluate your favourite HTTP client.

Read [`AGENTS.md`](AGENTS.md) first regardless of whether you're a human or an agent: it's the
contract, and it lists the specific ways each language's defaults will betray you (C#'s
culture-sensitive sort, Ruby's `split` dropping trailing empties, Java's UTF-16 `compareTo`).

## Reporting a problem

If a demo doesn't work, please include the language, the runtime version, and the actual output.
If it's a signature failure, run that language's test suite first — if the vectors pass, the
signing is correct and the problem is somewhere else, which is useful to know.

For anything about the fluxa platform itself rather than these demos, see
[docs.fluxa.cash](https://docs.fluxa.cash).
