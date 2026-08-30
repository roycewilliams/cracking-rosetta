# Maintaining cracking-rosetta

For people with commit rights and the three crackers installed.
`CONTRIBUTING.md` is the other half of this and is deliberately written for
someone who has neither.

The job is narrower than it looks. Almost everything mechanical is checked by
CI, so a review is really one question: **which claims did this change make,
and which of them can this machine settle?**

## Reviewing a contribution

```sh
git fetch origin pull/NN/head:pr-NN && git switch pr-NN

tools/validate.pl --changed main     # shape and identifiers, their entries only
tools/fmt.pl --all --check           # canonical form
tools/review-delta.pl --base main    # what the change CLAIMS
tools/review-delta.pl --base main --verify   # ...and settle what it can
```

`review-delta.pl` is the one that matters. A unified diff buries the single
most consequential line a contributor can write — `verified: "vector"` — as
one green line among forty. `review-delta.pl` compares the two sides as
*structures* and prints only what changed as a claim, graded:

- **PROVE** — a tier now says `vector`, or identifiers were added under a
  block that already does, or there are new vectors. Nothing here is
  trustworthy until this machine reproduces it. The tool prints the exact
  `verify-vectors.pl` line, and `--verify` runs it.
- **READ** — a claim no local run can settle: tier `upstream` or `asserted`,
  a relation's rationale, a note. Your judgement.
- **FYI** — covered by `validate.pl`, or inherently safe. A reformat reviews
  as "no claim changed", which is why contributors can run `fmt.pl` freely.

Because it compares structures, prose and formatting changes don't generate
noise, and an entry rewritten wholesale by a tool doesn't look like a rewrite
of its meaning.

## Why CI doesn't verify, and must not

`.github/workflows/validate.yml` runs `validate.pl`, `fmt.pl --check` and a
compile of every tool. It never runs a cracker.

That's not a limitation of hosted runners, it's the design. Tier `vector` is
the repository's only load-bearing claim. If a pull request could cause CI to
mark something `vector`, then a pull request could mark *anything* `vector`,
and the tier would mean nothing. Verification happens on a machine a
maintainer controls, or it doesn't happen.

So a green check means "well formed, and every identifier it names exists in
the committed inventories". It does not mean the mappings are true. That part
is your job, and `review-delta.pl` exists to tell you exactly how much of it
there is.

## Settling a claim

```sh
tools/verify-vectors.pl --only ENTRY --tool hashcat --tool john --tool mdxfind
```

It promotes a tool block to `vector` only when **every** identifier that block
lists recovers the entry's plaintext from the entry's hash. Anything less is
reported, not written.

A failure is not automatically a rejection. A vector that won't crack can mean
a wrong mapping, a wrong plaintext, a missing salt, or an encoding the tool
wants differently — and the exit status can't tell those apart. Ask.

Two rules that have each cost real time here:

- **A failed round-trip never demotes.** Silence about a failure is bad;
  turning a proven row into an unproven one because a run was misconfigured is
  worse.
- **Never promote a tier by editing YAML.** Run the tool. The tier records
  that a specific check passed on a specific date with a specific build; hand
  editing it makes the whole column a matter of trust again.

## The rest of the toolchain

| When | Run |
|---|---|
| Upstream released | the relevant `tools/extract-*.pl`, then `validate.pl` — an entry naming a retired identifier now fails |
| Data changed | `tools/render.pl` — but CI does this on push; you rarely need to |
| Vectors added anywhere | `tools/verify-vectors.pl --tool all` |
| Looking for missing John mappings | `tools/discover-john.pl`, then `tools/identify-john.pl` (the two search directions) |
| Expressions | `tools/expressions.pl` (transcribe, tier `upstream`), then `tools/derive-expressions.pl` (prove, tier `vector`) |
| Two entries share an expression | `tools/relate.pl` — writes both sides; never hand-write one |
| Refreshing upstream copies | `tools/fetch-upstream.sh`, committed on its own |

Every tool prints usage with no arguments and writes nothing without
`--apply`. Data goes to stdout, progress to stderr.

## Merging duplicate entries

`duplicate-of` with `distinction: none` is a contributor saying "nothing
separates these". Acting on it is a maintainer decision, because an `id` is a
published key: it's the filename, a link fragment in `docs/index.html`, and
the column `dist/rosetta.csv` is keyed on. Deleting one breaks whatever points
at it.

There is no settled policy yet for what a retired `id` should resolve to. Until
there is, merges stay proposals in the data. `tools/dedupe.pl` holds the
mechanics and is dry-run by default.

## Things that will bite you

- **`RosettaEmit`'s key order is an allowlist.** A key it doesn't know isn't
  an error — it just isn't emitted. Schema, `@ENTRY_ORDER` in
  `tools/lib/RosettaEmit.pm` and `validate.pl` must always change in the same
  commit. `fmt.pl` catches the resulting loss, so run it after any schema
  work.
- **John's pot echoes John's encoding, not your input.** A bare digest comes
  back `$dynamic_213$…`; `$2y$` comes back `$2a$`. Attribute a crack by the
  synthetic login and `--show`, never by searching the pot for the hash you
  submitted.
- **mdxfind reports the first internal type that reproduces a digest.** Pin
  the candidate with `-h '^TYPE$'` or you'll record a masking type instead of
  the real one.
- **mdxfind salted and userid types need `-F`, not `-f`.** The `s` and `u`
  flags in the inventory say which.

## Release and publishing

`render.yml` regenerates `docs/` and `dist/` on any change to `data/**`,
`tools/render.pl` or `tools/lib/**`, and commits only if the output actually
differs. It can't loop: it commits paths that aren't triggers. It needs
**Settings → Actions → General → Read and write permissions**.

The rendered table is meant to be served by GitHub Pages from **main /
`/docs`**.
