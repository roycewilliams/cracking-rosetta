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
most consequential line a contributor can write -- `verified: "vector"` -- as
one green line among forty. `review-delta.pl` compares the two sides as
*structures* and prints only what changed as a claim, graded:

- **PROVE** -- a tier now says `vector`, or identifiers were added under a
  block that already does, or there are new vectors. Nothing here is
  trustworthy until this machine reproduces it. The tool prints the exact
  `verify-vectors.pl` line, and `--verify` runs it.
- **READ** -- a claim no local run can settle: tier `upstream` or `asserted`,
  a relation's rationale, a note. Your judgment.
- **FYI** -- covered by `validate.pl`, or inherently safe. A reformat reviews
  as "no claim changed", which is why contributors can run `fmt.pl` freely.

Because it compares structures, prose and formatting changes don't generate
noise, and an entry rewritten wholesale by a tool doesn't look like a rewrite
of its meaning.

## Why CI doesn't verify, and must not

`.github/workflows/validate.yml` runs `validate.pl`, `fmt.pl --check`,
`check-numbers.pl --tracked`, `check-upstream.pl --check`, an ASCII check and a
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
wants differently -- and the exit status can't tell those apart. Ask.

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
| Upstream released | the relevant `tools/extract-*.pl`, then `validate.pl` -- an entry naming a retired identifier now fails |
| Data changed | `tools/render.pl` -- but CI does this on push; you rarely need to |
| Vectors added anywhere | `tools/verify-vectors.pl --tool all` (`--only` is repeatable, so verify just the delta) |
| An entry has no vector, or a tool block is stuck below tier `vector` | `tools/seed-vectors.pl --report`, then `--apply` (add `--fill` for the second case) -- it seeds the publishing tool's own published example and verifies before writing |
| An mdxfind type exists in `data/tools/mdxfind.yaml` and not in the installed binary | `tools/attach-mdxfind-ahead.pl --report`, then `--apply`. The inventory tracks upstream's releases and the binary is whatever is installed; mdxfind cannot prove a type it does not have, and says so only by printing "No hash types selected" and exiting 0. hashpipe is pinned with `-c` instead and the row is written at tier `upstream` naming both binaries and the command that promotes it. Rows it cannot attach become their own entry via `tools/seed-orphans.pl --tool mdxfind --via-hashpipe` |
| A row names one tool and should name three | `tools/discover-hashcat.pl`, `tools/discover-mdxfind.pl`, `tools/discover-john.pl` -- one per column, same proof standard: the identifier goes on the row because that tool cracked THAT ROW'S vector under it |
| Looking for missing John mappings | `tools/discover-john.pl`, then `tools/identify-john.pl` (the two search directions) |
| Expressions | `tools/expressions.pl` (transcribe, tier `upstream`), then `tools/derive-expressions.pl` (prove, tier `vector`) |
| Two entries share an expression | `tools/relate.pl` -- writes both sides; never hand-write one |
| Refreshing upstream copies | `tools/fetch-upstream.sh`, committed on its own -- it writes the commit and date into `vendor/*/PROVENANCE.md` itself; then `tools/check-upstream.pl --check -v` |
| A known disagreement with an upstream document | `data/upstream-disagreements.yaml`, executed by `tools/check-upstream.pl`. Add a record only when the disagreement has been MEASURED; delete it the day the record reports `converged`, which means upstream fixed it |
| Giving an entry a recognisable vector | `tools/vanity.pl --entry ID` (`--apply` to write) -- a second vector whose digest starts `dec0ded`, alongside the plain one, never over it |

Every tool prints usage with no arguments and writes nothing without
`--apply`. Data goes to stdout, progress to stderr.

## Curation: the decisions no tool can make

The machine passes are done. What's left is a person knowing things: entries
with no `category:` (the sheet's own `class` column, defined in 2023 and never
filled), entries with no expression and nothing said about why, merge
proposals, and expressions that don't reproduce their own vectors.

`tools/curate.pl --list` prints how many of each are open today. This file
deliberately does not: the answer moves every session, and a number here would
be wrong before anyone read it.

`tools/curate.pl` is a question queue for exactly that. One question at a
time, every fact the repo already knows printed above it, usually one
keystroke to answer:

```sh
tools/curate.pl --list                      # what's open
tools/curate.pl --kind category --limit 20  # ten minutes' worth
tools/curate.pl --report                    # the answers, as Markdown
tools/curate.pl --apply                     # write what can be written
```

Answers append to `tmp/curation.tsv` as you give them, so quitting costs
nothing and re-running skips what's answered. **Nothing touches
`data/algorithms` until `--apply`**, and `--apply` deliberately writes only
two kinds:

- `category` -- a closed vocabulary; the answer *is* the value.
- `denotation` -- free text with `source: human`, which is what that field is
  for: untiered, because nothing can round-trip it.

Everything else is recorded and reported, never applied. A merge is a
maintainer's edit -- see the next section -- and an expression must be proven by
john, not accepted because someone typed it. `--report` prints the held
answers as Markdown, which is the format to hand to whoever -- or whatever --
acts on them next.

Run `validate.pl` and `fmt.pl --all --check` after `--apply`; it tells you to.

## Merging duplicate entries

`duplicate-of` with `distinction: none` is a contributor saying "nothing
separates these". Acting on it is a maintainer decision, because an `id` is a
published key: it's the filename, a link fragment in `docs/index.html`, and
the column `dist/rosetta.csv` is keyed on. Deleting one breaks whatever points
at it.

A retired `id` becomes a **tombstone** (decided 2026-08-30), so acting on a
proposal no longer breaks anything that points at it. The merge itself is
ordinary: fold the loser's `aliases:`, `legacy:`, `vectors:` and tool
identifiers into the survivor, re-verifying anything you fold that the
survivor has not proven for itself. Then reduce the loser's file to the
redirect:

```yaml
id: "ripemd320"
name: "ripemd320"
status: "merged"
merged_into: "rmd320"
relations:
  - kind: "duplicate-of"
    entry: "rmd320"
    distinction: "none"
    note: "merged 2026-08-30 on <who decided>, because <why>"
notes: "Tombstone. ..."
```

`validate.pl` checks the shape: a tombstone must carry `merged_into` and a
mirrored `duplicate-of` edge, must name a survivor that exists and is not
itself a tombstone, and must carry no claims at all. It is left out of every
count. `dist/rosetta.csv` keeps a row for the dead id with a `merged_into`
column, so a consumer joining on it is told where it went.

`tools/dedupe.pl` holds the mechanics and is dry-run by default; it predates
this decision and does not yet write the tombstone, so check its output.

**Not every proposal should be merged.** Two of the first four answered were
refused: mdxfind publishes three type indices for `md4(utf16($p))` and the
`NTLMH` row is where a reader arrives with that name. That answer is
`same-computation` with `distinction: naming`, which records that the merge
was considered and declined -- as opposed to `none`, which records that one is
still owed.

## At publication

The repository is private on purpose until it is ready. When it flips, in this
order:

1. **Make it public, and enable Pages on main / `/docs`.** Both are GitHub UI
   settings. `docs/index.html` is the front door; nothing else here is.
2. **File the question queue, regenerated at that moment:**

   ```sh
   tools/curate.pl --issues > tmp/issues.sh   # writes nothing, files nothing
   $EDITOR tmp/issues.sh                      # read it; cut what you do not want
   sh tmp/issues.sh
   ```

   Regenerate rather than filing a saved batch. The queue shrinks as the tools
   resolve things, sometimes by half in a single session, and a stale batch
   files questions that already have answers. The script creates its own
   `curation` label and files nothing until you run it.

3. **Re-render**, so the counter, `GAPS.md` and `OPEN-QUESTIONS.md` match what
   is being published: `tools/render.pl`, then `tools/validate.pl`.
4. **Tell Cynosure Prime it is live.** Much of the verified seed data is
   theirs and they are expecting it.

## Things that will bite you

- **`RosettaEmit`'s key order is an allowlist.** A key it doesn't know isn't
  an error -- it just isn't emitted. Schema, `@ENTRY_ORDER` in
  `tools/lib/RosettaEmit.pm` and `validate.pl` must always change in the same
  commit. `fmt.pl` catches the resulting loss, so run it after any schema
  work.
- **John's pot echoes John's encoding, not your input.** A bare digest comes
  back `$dynamic_213$...`; `$2y$` comes back `$2a$`. Attribute a crack by the
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
**Settings -> Actions -> General -> Read and write permissions**.

The rendered table is meant to be served by GitHub Pages from **main /
`/docs`**.
