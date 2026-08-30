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
    CONTRIBUTING.md          For someone adding information; assumes no crackers.
    MAINTAINING.md           For someone reviewing a contribution; assumes them.
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

The same four tiers apply to `expression:` via `expression_proof:` — see
**Expression language** below. It is the same kind of claim and deserves the
same audit trail.

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
  `dynamic_2`, `MD5x03` is `dynamic_3`. Never strip the suffix, and check it
  on the way back in: 42 entries declaring two iterations were seeded with
  their type's single-iteration self-test vector and reached tier `vector`
  because the verifier accepted any suffix. `tools/audit-iterations.pl`
  measures the count a vector actually matches at.
- **Name separator drift.** The source sheet wrote `HAV128_4` where mdxfind
  writes `HAV128-4`. Normalize by stripping non-alphanumerics before matching;
  store the tool's exact spelling.
- **Upstream can name modes that do not exist.** mdxfind's map references
  hashcat modes `11780`, `46100`, `67000`, none of which exist in hashcat
  v7.1.2-549. Report, do not silently drop.
- **Sheet-era junk.** `NOTSUPPORTED`, `MD5AUTOMATICPARTIALMATCH` and
  `MD5UCWITHI2MD5UCX2` appear in the mdxfind column but are not types.
  `WLR1` was on that list and should not have been: it is `WRL1`
  (Whirlpool-1) with the letters transposed, and both mdxfind pinned to
  `WRL1` and john's `whirlpool1` reproduce the sheet's vector. Check a
  suspected non-type against the inventory before writing it off.
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

`tools/expressions.pl` populates both fields from `john --list=subformats`,
which states what each of john's 474 dynamics computes in the syntax
`--format=dynamic='...'` takes back. It writes only where the john block
reached tier `vector` and every identifier that block names prints the same
expression, so the field is transcription rather than interpretation.

`tools/derive-expressions.pl` is the other direction, and it is the reason an
expression can be *proven* rather than proposed. **John's dynamic compiler
takes an expression on the command line**, so a candidate never has to be
believed: hand it to john against the entry's own vector and either it
recovers the entry's own plaintext or it does not. Candidates come from three
redundant generators — the `name:` field, the entry `id` slug, and the mdxfind
type name — and every one of them **bails on the first token it does not
know**. That rule is what keeps the tool honest: `MD5CAP`'s `CAP` is not in
the vocabulary, so no candidate is emitted, whereas silently dropping the
token would emit `md5($p)`, which john would happily "prove" because `cap()`
is a no-op on a lowercase digest. The function vocabulary is harvested from
john's own subformat listing, never hand-written.

Two guards, both non-negotiable. **Every vector the entry carries must fall,
not the first** — an entry with three vectors and a candidate that cracks two
has found a coincidence, which is exactly how `dynamic_1011` looked like
`MD5PASSMD5`. And **if two different expressions each reproduce every vector,
nothing is written**: they agree on this entry's inputs, they need not agree
in general, and choosing between them is curation.

A proven expression is also an operational answer — `john
--format=dynamic='haval128_3(md5($p))'` is a command someone can run today on
an entry that has no named john format at all. It belongs in
`john_dynamic_expr:`, **never in `tools.john.cpu`**: an ad-hoc expression is
not a john format identifier and putting it in the identifier column would
inflate john's coverage with something no `--list=formats` will ever show.

### The expression carries its own tier

`expression:` is a gate — `validate.pl` fails a build where two entries claim
the same one — so it says how it was established, in the same vocabulary the
per-tool blocks use:

    expression: "haval128_3(md5($p))"
    john_dynamic_expr: "dynamic=haval128_3(md5($p))"
    expression_proof:
      verified: "vector"
      verified_at: "2026-08-29"
      verified_with: "john 1.9.0-jumbo-1+bleeding-9a336d800a"
      note: "round-tripped as --format=dynamic=<expr> against every vector"

Without it a transcription and a round-trip are indistinguishable, and the
first awkward collision becomes an argument for weakening the rule. The tiers
mean here what they mean everywhere:

- `vector`   — this exact string was compiled by john and recovered the
               entry's own plaintext from its own hash. Only
               `derive-expressions.pl` may write it.
- `upstream` — john's `--list=subformats` states it for an identifier the
               entry already proved. `expressions.pl` writes this and nothing
               stronger: what was round-tripped is the *identifier*.
- `asserted` — a human said so.
- `absent`   — this algorithm has no expression in the dynamic language.

`validate.pl` enforces the pairing: an `expression:` with no
`expression_proof:` fails, `vector` with no vectors fails, and `absent`
alongside an expression fails.

### `denotation:` — no expression, but still a way to refer to it

`absent` on its own leaves a row's expression column empty and says nothing
useful to a reader. So the entry records how people actually refer to the
algorithm:

    expression_proof:
      verified: "absent"
      note: "john's dynamic expression vocabulary has no hmac(), so this
             construction cannot be written as an expression; that is separate
             from whether john has a FORMAT for it"
    denotation:
      text: "hmac(\"sha1\", $plain, $salt)"
      source: "sheet"

`text` is a pseudo-expression in a language richer than john's dynamic
(`md5(base64_encode($plain))`), or simply the label a suite or standard uses
(`PBKDF2-HMAC-SHA256`, `7-Zip`). It is deliberately **not tiered** — nothing
can round-trip it — so it carries a `source:` instead and is never an
unattributed human claim. It is illegal alongside `expression:`: an entry with
both says the same thing twice at two strengths and a reader cannot tell which
to believe.

`--denote` writes this pair, and only where `absent` is a **checkable fact**
rather than a shrug: the name is already expression-shaped and at least one
function in it is not in the vocabulary harvested from john. That is a lookup,
not an opinion. Note what it does *not* say — john has formats for HMAC-SHA1
and for bcrypt; it has no `hmac()` or `bcrypt()` token in the dynamic
*expression* language, and those are different sentences.

Entries whose name is not expression-shaped (`7ZIP`, `AIX-MD5`, `Tiger Tree
Hash`) are left alone rather than bulk-marked, because "no candidate could be
generated" is a fact about our generators, not about john.

## Collisions: when two entries mean the same thing

The moment expressions existed, nine of them turned out to be claimed by more
than one entry. That is not noise — it is the `id` being asked to carry four
independent facts at once: the **computation**, the **representation** (hex
case, base64, a `$1$` wrapper), the **deployment** (Joomla, vBulletin 3.8.5,
osCommerce — which hashcat gives separate modes), and the **tool identifier**.
Only the last was ever modelled.

So an entry carries three fields for it. `category:` names the axis it sits on
— `primitive`, `composite`, `iterated`, `encoding`, `application`, `protocol`,
`kdf` — with `application:` and `application_version:` for a product row.
`relations:` is a typed, symmetric edge list:

    relations:
      - kind: "same-computation"
        entry: "md5-pass-salt"
        distinction: "application"
        note: "hashcat separates these: mode 11 assumes Joomla's fixed-length
               salt, mode 10 is the generic construction"

`kind` says what the relationship is — `same-computation`, `encodes`,
`input-encoding`, `iterates`, `truncates`, `collides-on-subset`,
`duplicate-of`. `distinction` says why both rows nonetheless exist —
`application`, `encoding`, `input-encoding`, `iteration`, `truncation`,
`salt-convention`, `none`. `none` is legal only with `duplicate-of`, which is
how a merge gets proposed in data rather than in a comment.

`tools/relate.pl` writes edges, both sides at once. Never hand-write one side:
a relation only one of the two files states is a fact whichever file the
reader opens first decides whether they learn.

`validate.pl` enforces it. **Two entries claiming the same `expression` must
reach each other through `same-computation`, `encodes` or `duplicate-of`
edges, or the run fails.** That is what makes the expression a key rather than
a decoration. It also checks that every edge is mirrored and points at a real
entry, that `distinction: none` appears only on a `duplicate-of`, and that
`collides-on-subset` carries a note naming the inputs on which the two agree.

Three rules that are not the validator's job:

- **One entry is one computation.** If you are writing a second, different
  algorithm into `aliases:`, you need a second entry. `aliases:` is for other
  *names* of the same computation.
- **Record the trap, not the mapping**, when a tool cracks a vector without
  denoting the algorithm. `md5cap` is `cap(md5($p))`, a no-op on a lowercase
  digest, so john's `dynamic_2` recovers its vector; that is a
  `collides-on-subset` edge, not a john mapping.
- **`id` never changes.** It is the filename stem, a URL fragment in
  `docs/index.html` and the key in `dist/rosetta.csv`. A rename is a new entry
  plus a `duplicate-of` edge and an alias on the survivor, never an `mv`.

The full design, the options weighed against it and what changed on contact
with the code are in `ACTION-PLAN.md` §11.

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
