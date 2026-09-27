# HUMAN.md - orientation and maintenance runbook for a person

You are looking at **cracking-rosetta**, a cross-reference of password-cracking
algorithm identifiers across hashcat, John the Ripper, and mdxfind/hashpipe.
This file is the door in for a human maintainer: what the thing is, the handful
of workflows you will actually run, and what will bite you.

It is deliberately not a rewrite of the other docs:

| If you want... | Read |
|---|---|
| Orientation and the routine maintenance recipes | **this file** |
| What a consumer can depend on, the data contract, the tiers | `README.md` |
| The authoritative rulebook: prime directive, every pitfall, the relations and expression models | `CLAUDE.md` |
| How to add or correct an entry (assumes you are not a cracker) | `CONTRIBUTING.md` |
| How to review a contribution (assumes you are) | `MAINTAINING.md` |
| Session handoff, current numbers, open work (private, untracked) | `STATE.md` |

`CLAUDE.md` is written as instructions to an AI assistant and reads as a long
list of hard-won prohibitions. It is authoritative, but it is a poor first
introduction. Start here, reach for it as reference.

---

## 1. The mental model, in one minute

The repository has **two layers**, and every workflow below respects the line
between them:

- **`data/tools/*.yaml` - the inventory (GENERATED).** A mechanical dump of what
  each tool actually supports, one file per tool, regenerated from the binary.
  **You never hand-edit these.** If a mode or format is missing, you re-run the
  extractor, not an editor.
- **`data/algorithms/*.yaml` - the mappings (CURATED).** Human judgment about
  which identifiers across tools denote the same algorithm. One file per
  algorithm. This is the pull-request surface and the thing worth protecting.

Everything under `docs/` and `dist/` is **generated** from `data/algorithms/`.
Do not edit it; it is overwritten on the next render.

Every mapping carries a **tier** saying how well it is known: `vector` (this
repo cracked the test vector under that exact identifier - proven), `upstream`
(a project that verifies by recomputation asserts it), `asserted` (a human said
so), `absent` (the tool does not support it). **A tier is only ever moved by
re-running the check that earns it.** No tool here promotes on confidence, and a
failed round-trip never silently demotes anything.

---

## 2. The tools you will actually run

There are ~60 scripts in `tools/`; most are one-time surgical tools from the
build-out. For routine maintenance you touch about eight. All take `--help`, all
follow the house convention (no args prints usage and exits 2, status to stderr,
data to stdout).

| Script | Job |
|---|---|
| `upstream-refresh.pl` | **Check for and pull new upstream releases, rebuild, and report the delta.** The front door for keeping current. |
| `validate.pl` | The PR gate. Shape-checks entries and resolves every identifier against the inventories. |
| `fmt.pl` | Canonical YAML, and a round-trip loss check that catches a misspelled key. |
| `render.pl` | Regenerate `docs/` and `dist/` from `data/algorithms/`. |
| `verify-vectors.pl` | Round-trip crack a vector and promote to tier `vector`. Needs the tools installed (and a GPU for hashcat). |
| `review-delta.pl` | Show what a change actually *claims*, graded PROVE / READ / FYI. |
| `fetch-upstream.sh` | Refresh the vendored upstream catalogs in `vendor/`. |
| `check-upstream.pl` | Reconcile `data/upstream-disagreements.yaml` after a catalog refresh. |
| `availability.pl` | Rebuild `dist/availability.csv` (which release first carried each identifier). |

---

## 3. Workflow: keep the upstreams current  (the common one)

This repository tracks each tool's **upstream tip, not its releases**, so the
suites drift out from under it constantly. `tools/upstream-refresh.pl` is the
whole loop, with the traps that used to live only in `CLAUDE.md` encoded as
guards (it builds mdxfind CPU-only, refuses a GPU-linked binary, computes the
delta by identifier, and cross-references the proven corpus).

**Step 1 - see what moved (read-only, safe, no changes):**

```
tools/upstream-refresh.pl check
```

It fetches each upstream, prints how far behind you are, the commit subjects in
between (your behavior-change signal), and whether a committed inventory already
lags a binary you built earlier. john is report-only, because its tree is
royce-owned and this account cannot build it.

**Step 2 - pull, rebuild, and see the inventory delta:**

```
tools/upstream-refresh.pl update                 # all buildable tools
tools/upstream-refresh.pl update --only hashcat  # just one
```

For each tool that is behind it pulls (fast-forward only), builds, regenerates
the inventory into a **scratch** file, and prints the delta: modes/types/formats
added, removed, changed. Crucially, **every removed or changed identifier that a
tier-`vector` row names is flagged** - those are the mappings the new build may
have invalidated, and they are the work the move creates. Nothing is written to
`data/tools/` yet.

If you already built a newer binary and only the inventory is stale, skip the
pull and build:

```
tools/upstream-refresh.pl update --no-build --only hashpipe
```

**Step 3 - install the regenerated inventories and eyeball the diff:**

```
tools/upstream-refresh.pl update --write
git diff data/tools/                             # confirm the diff is what the report said
```

**Step 4 - re-verify what the move touched.** For each proven row the report
flagged, re-run the round trip; if it still cracks, the tier holds, if not, the
mapping needs a human (do NOT let it silently demote):

```
tools/verify-vectors.pl --tool <tool> --only <entry-id>
```

**Step 5 - refresh the vendored catalogs and reconcile (if hashpipe/mdxfind
moved),** then re-render and validate (workflows 4 and 6 below):

```
tools/upstream-refresh.pl update --catalogs      # or tools/fetch-upstream.sh
tools/check-upstream.pl                          # a spent disagreement fails here
```

**What this workflow deliberately does not do:** touch `data/algorithms/`. It
regenerates the mechanical layer and tells you what changed. Deciding what a new
type means, or whether a changed one still maps where it did, is curation - a
person's job, done with the tools in workflow 4.

**Notes / gotchas specific to the refresh:**

- **mdxfind must be CPU-only.** The script enforces it (`make OPENCL_GPU=`), and
  refuses to extract a binary whose `-h` output carries ` [GPU]`. A GPU-linked
  mdxfind contends for the card (which has corrupted data on this host) and
  silently drops the types whose `-h` row it marks ` [GPU]` -- 109 of them,
  measured 2026-09-06 -- from the inventory. Never "simplify" its build to a
  bare `make`.
- **hashpipe build:** the script runs a plain `make`, which relinks in seconds
  against the vendored `libsph.a`. If it fails for a missing archive, run
  `make deps` once yourself in the clone - the script will not, because `deps`
  clones and builds a dozen crypto libraries and that is a decision.
- **john** needs the operator: rebuild with `newjohn`, then
  `tools/extract-john.pl --binary <run/john> > data/tools/john.yaml`.
- Builds are minutes long. Run scratch and logs land under
  `tmp/upstream-refresh/<timestamp>/`.

---

## 4. Workflow: add or correct a mapping

1. Edit exactly one file under `data/algorithms/` (or create one; the filename
   stem is the permanent `id`). `CONTRIBUTING.md` has the field-by-field guide.
2. Canonicalize and shape-check:
   ```
   tools/fmt.pl --all
   tools/validate.pl --changed        # resolves every identifier you named
   ```
3. See what you actually claimed:
   ```
   tools/review-delta.pl              # graded PROVE / READ / FYI
   ```
4. Prove what you can (workflow 5). Do not inflate a tier: an honest `asserted`
   with a note beats a hopeful `vector`.
5. Re-render (workflow 6) and commit `data/algorithms/` plus the regenerated
   `docs/`+`dist/` together.

**Rules that are not negotiable** (validator or convention enforces them):

- An **`id` is forever** - filename stem, URL fragment, CSV key. To retire one,
  merge with `tools/merge.pl`, which leaves a tombstone; never `mv` or delete.
- **One entry is one computation.** A second, different algorithm needs a second
  entry, not an extra alias.
- Never hand-edit `data/tools/` or `vendor/`.

---

## 5. Workflow: prove a vector / move a tier

```
tools/verify-vectors.pl --tool all           # everything provable on this host
tools/verify-vectors.pl --tool mdxfind --only <entry-id>
```

It round-trips the entry's own vector under each named identifier and promotes
to tier `vector` only on a byte-exact (or explicitly conceded) crack. It needs
the tools installed and a GPU for hashcat. A failure is a *report*, never a
demotion - a vector that will not crack might be a wrong mapping, a wrong
plaintext, or a missing salt, and the exit status cannot tell them apart. See
`CLAUDE.md` for the many ways a "failure" is really a question about the input.

After anything that moves tiers, re-derive `status:` and re-render:

```
tools/status-sweep.pl
tools/render.pl
```

---

## 6. Workflow: regenerate the published artifacts

Any change to `data/algorithms/` must be followed by a render, or `docs/` and
`dist/` drift from the source of truth (CI does this too, on push):

```
tools/render.pl        # -> docs/index.html, docs/ROSETTA.md, dist/rosetta.{csv,json}, README counter
```

`dist/availability.csv` is the exception: it is built from the upstream git
clones, not from `data/`, so it is refreshed by hand and only when an inventory
changed:

```
tools/availability.pl > dist/availability.csv
```

---

## 7. Where things live, and what will bite you

- **The canonical binaries are the local builds, not the installed ones**, under
  `/home/claude/src/upstream/{hashcat,mdxfind,hashpipe}`. The installed
  `/usr/local/bin` copies are root/royce-owned, older, and serve only as
  verifiers for what they already have. `upstream-refresh.pl` and the extractors
  point at the local builds; the verifiers resolve a binary via `--<tool>`, then
  `$HASHCAT`/`$JOHN`/`$MDXFIND`/`$HASHPIPE`, then a built-in default.
- **`verified_with:` must name the binary that RAN**, never the one that is
  installed and never the inventory's version. This is load-bearing: on this
  host the local mdxfind build has been several revisions ahead of the installed
  one, and crediting the wrong build has produced real errors.
- **Never run `git` as `royce` in this `claude`-owned tree** (corpus Rule Zero):
  even `git status` rewrites `.git/index` under the invoking user and can lock
  the owner out. The refresh wrapper only ever runs git with `-C` against the
  out-of-tree clones.
- **`STATE.md` is private and untracked** (see the `.gitignore` line). It holds
  host paths and working notes that must not reach the public repo. It is
  versioned only in a private bare mirror; run its `sync-state.sh sync` after a
  substantial edit. Never `git add` it here.
- **Everything is ASCII** in docs, code and data, enforced by `check-non-ascii.py`
  on PATH. No em-dashes; use a spaced hyphen.

---

## 8. Before you commit

```
tools/fmt.pl --check          # canonical form (CI runs this)
tools/validate.pl             # the full gate (CI runs this)
tools/render.pl               # regenerate docs/ + dist/ if data changed
git diff dist/                # confirm the export contract did not widen by accident
```

Commit `data/`, `docs/` and `dist/` for one logical change together. Keep the
message and PR body lean - a three-line diff does not need a wall of narrative.
