# CLAUDE.md — cracking-rosetta

Cross-reference ("rosetta stone") of password-cracking algorithm support and
identifiers across hashcat, John the Ripper, mdxfind/hashpipe, and — for
historical reference only — Alec Muffett's Crack.

Migrated from a Google Sheet:
`https://docs.google.com/spreadsheets/d/1SBv-oRbXb8OapSD1BSPClPXIfiWOL2oH_zTls4sz1rk`

## Prime directive

**Never assert a mapping that has not been reproduced.** A row saying
"hashcat 2811 == dynamic_12 == MD5-MD5SALTMD5PASS" is only trustworthy if a
test vector was actually cracked by each named tool under that exact
identifier. Unverified mappings are allowed, but must be labelled as such
(see Verification tiers). This mirrors upstream Cynosureprime practice — see
the header of `hashpipe/john_map.h`: *"Formats whose vectors did not verify
are absent rather than guessed."*

## Repository layout

    data/tools/*.yaml        GENERATED. Per-tool inventories. Never hand-edit.
    data/algorithms/*.yaml   CURATED. One file per algorithm. The PR surface.
    schema/                  JSON Schema for both file kinds.
    tools/                   Extractors, validators, renderers (Perl).
    docs/ROSETTA.md          GENERATED. Flat human-readable table.
    dist/rosetta.{csv,json}  GENERATED. Machine consumption.
    tmp/                     Scratch. Not committed.

### Two-layer split — why

`data/tools/` is a mechanical dump of what each tool *actually supports*,
regenerated from the canonical binary. `data/algorithms/` is human judgement:
which identifiers across tools denote the same algorithm. Keeping them apart
means an upstream release regenerates one layer without touching curation,
and diffs stay reviewable.

One file per algorithm (not one big table) is deliberate: contributors touch
exactly one small file, merge conflicts are near-impossible, `git blame` is
meaningful per algorithm, and CODEOWNERS can route by path. The flat views
people expect are regenerated into `docs/` and `dist/`.

## Canonical sources

| Tool | Binary / source | Extraction command |
|---|---|---|
| hashcat | `/usr/local/bin/hashcat` (v7.1.2-549-g8a15e210b) | `hashcat --hash-info` |
| john | `/usr/local/scripts/johnl` -> `/usr/local/src/sec/crack/john-latest/run/john` | `john --list=format-details` |
| mdxfind | `/usr/local/bin/mdxfind` (RCS 1.540, 2026-08-22) | `mdxfind -h` |
| hashpipe | not built locally | upstream `HASH_TYPES.md` |
| Crack | not present | hand-maintained, frozen |

Upstream, for drift detection and as seed data:

- `github.com/Cynosureprime/mdxfind` — `HASH_TYPES.md`
- `github.com/Cynosureprime/hashpipe` — `HASH_TYPES.md`, `john_map.h`

**hashpipe is not a separate column.** Its type list was diffed against the
local mdxfind binary: 1000 vs 1001 types, zero name mismatches, zero
hashcat-mode mismatches (mdxfind has one extra index, e426). Record hashpipe
as an alias of mdxfind until that stops being true; `tools/extract-hashpipe.pl`
exists to detect divergence, not to populate a column.

## Verification tiers

Every per-tool mapping carries `verified:`:

- `vector`   — a test vector was round-tripped locally by that tool under that
               exact identifier. The only tier that means "proven".
- `upstream` — asserted by an upstream project that verifies by recomputation
               (mdxfind's `Hashcat mode` column, hashpipe's `john_map.h`).
- `asserted` — a human said so; no reproduction on record.
- `absent`   — that tool does not support this algorithm.

Also record `verified_at` (ISO date) and `verified_with` (tool version string).
Never promote a tier without re-running the check.

## Round-trip verification recipes

These are proven working in this environment.

    # hashcat  (GPU present: RTX 4060 Ti; nvmlInit warning is benign)
    hashcat -m <mode> -a 0 --quiet --potfile-disable --self-test-disable \
        <hashfile> <wordlist>

    # mdxfind  — pin the type; -i 1 unless the type is iterated
    mdxfind -h '^<TYPE>$' -f <hashfile> -i 1 <wordlist>
    # prints e.g.:  MD5x01 482c811da5d5b4bc6d497ffa98491e38:password123

    # john
    john --format=<label> --test=0
    john --format=<label> --wordlist=<wordlist> <hashfile>

mdxfind also accepts hashcat modes directly (`mdxfind -m 0`, `-m e1`,
`-m e1-e10`), which is itself a usable cross-check.

## Known pitfalls

- **Type masking (mdxfind).** mdxfind reports the *first* internal type that
  reproduces a digest. `MD5CAP` is `cap(md5(pass))`, a no-op whenever the
  digest starts with a digit, so it is byte-identical to plain `MD5`. Always
  pin the candidate type with `-h '^TYPE$'` and require *every* sampled vector
  of the format to verify. Break ties toward the lowest `eN`.
- **Iteration suffix is identity.** `MD5x01` != `MD5x02`; `MD5x02` is
  `dynamic_2`, `MD5x03` is `dynamic_3`. Never strip the suffix.
- **Name separator drift.** The source sheet wrote `HAV128_4` where mdxfind
  writes `HAV128-4`. Normalize by stripping non-alphanumerics before matching;
  store the tool's exact spelling.
- **Upstream can name modes that do not exist.** mdxfind's map references
  hashcat modes `11780`, `46100`, `67000`, none of which exist in hashcat
  v7.1.2-549. Report, do not silently drop.
- **Sheet-era junk.** `NOTSUPPORTED`, `MD5AUTOMATICPARTIALMATCH`,
  `MD5UCWITHI2MD5UCX2`, `WLR1` appear in the mdxfind column but are not types.
- **john is not executable by every user here.** `run/john` and `run/*.conf`
  are `0750 royce:royce`. Extraction must run as `royce`, or the mode must be
  widened. `src/*.c` is world-readable but only yields ~114 of ~403 formats;
  do not use it as a substitute.

## Expression language

The sheet's dormant "Primitives" tab wanted a meta-language for expressing
algorithms. Do not invent one. mdxfind now ships a full expression compiler
(`hx.lex.c`, `hx.tab.c`, `hx_ast.c`, `hx_compile.c`, `hx_vm.c`,
`codegen/hx_emit_primitives.c`) and John has `--format=dynamic='EXPR'`.
Record both, canonical field is the hx-style expression:

    expression: md5(md5($p).$s)
    john_dynamic_expr: dynamic=md5(md5($p).$s)

The expression is the semantic join key — it is what lets a validator assert
that two tools' identifiers really do denote the same thing.

## Conventions

- ETL and tooling in **Perl** (see global CLAUDE.md). The one-shot sheet
  importer is Python only because `openpyxl` is the practical xlsx reader;
  flag any further Python additions.
- Data files are YAML, UTF-8, LF, 2-space indent, keys in schema order.
- Generated files carry a `# GENERATED by tools/<x> — do not edit` header and
  the source tool version.
- Scripts: no args => usage + exit 2. `--verbose` to stderr, data to stdout.
  Counts and elapsed time to stderr on bulk runs.
- Scale is small — ~1000 mdxfind types, ~600 hashcat modes, ~400 john formats.
  Plain hashes are fine; no need for anything cleverer.
