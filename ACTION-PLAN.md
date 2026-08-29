# cracking-rosetta — action plan (for review)

Status: **proposal**. Nothing below is built yet except the survey evidence,
which was measured in this environment on 2026-08-29.

---

## 1. Where the sheet actually stands

Exported all three tabs and diffed them against the canonical tools.

| Tab | Size | State |
|---|---|---|
| `Rosetta` | 1084 data rows x 13 used columns | 438 rows fully blank; 200 rows carry data but no algorithm name; 435 unique algorithm names |
| `Primitives` | ~70 rows | Dormant draft of an algorithm meta-language |
| `refs` | 17 rows | Link list. Self-declared "Last updated 2023-05-04" |

### Coverage against the canonical tools

| Tool | Supported today | Covered by sheet | Gap |
|---|---:|---:|---:|
| hashcat v7.1.2-549 | 593 modes | 82 | **511 (86%)** |
| mdxfind RCS 1.540 | 1001 types | 518 | **483 (48%)** |
| John (jumbo, bleeding) | ~403 formats | 55 CPU / 56 GPU | **~348 (86%)** |

267 hashcat modes are mapped by *neither* the sheet nor mdxfind's built-in
`Hashcat mode` column. That is the genuine whitespace.

### Column health

Five of thirteen columns are effectively dead: `class` (0 filled), `Notes`
(0), `Hashcat-legacy mode` (5), `hashes.org comment` (3), `MDXfind
extra_params` (7). Two more columns — `Hashkiller-accepted format` and
`hashes.org algo` — point at services that no longer exist. They still have
archival value for reading old cracking write-ups, so demote them into a
`legacy:` block rather than deleting them.

### Data defects found

- Separator drift: sheet `HAV128_4` vs mdxfind `HAV128-4`, ~47 rows. Mostly
  false mismatches; needs normalization, not re-research.
- Four non-types in the mdxfind column: `NOTSUPPORTED`,
  `MD5AUTOMATICPARTIALMATCH`, `MD5UCWITHI2MD5UCX2`, `WLR1`.
- Duplicate algorithm names, e.g. `md5(md5($plain).$salt)` appears 3x.
- Only 547 of 1084 rows carry an example hash, so most rows cannot currently
  be verified even in principle.

---

## 2. What upstream already gives us for free

The single biggest finding of the survey: **Cynosureprime has already done a
large, verified chunk of this work, and publishes it in machine-readable form.**

- `mdxfind/HASH_TYPES.md` and `hashpipe/HASH_TYPES.md` — a Markdown table of
  every type: index, name, hashcat mode(s), and a complete self-test vector
  as `hash[:salt]:password`. That is 1000 algorithms *with test vectors*,
  which is exactly the corpus needed to verify anything.
- mdxfind ships hashcat mappings for **296 types covering 325 distinct modes**.
- `hashpipe/john_map.h` — **125 John dynamic formats** mapped to mdxfind
  types, each confirmed by recomputation against John's own test vectors
  (9672 vectors harvested across 403 formats).

Seeding from these two sources gets us further on day one than the sheet
reached in years, and it arrives pre-verified.

**hashpipe needs no column and no local build.** Its type list diffed against
the local mdxfind binary: 1000 vs 1001 types, **zero** name mismatches, **zero**
hashcat-mode mismatches (mdxfind has one extra index, e426). Treat hashpipe as
an alias of mdxfind; keep a drift check so we find out if that changes.
Revisit when you get it compiling.

---

## 3. Proposed structure

    data/tools/*.yaml        GENERATED per-tool inventories — never hand-edited
    data/algorithms/*.yaml   CURATED, one file per algorithm — the PR surface
    schema/*.schema.json     validation contract
    tools/*.pl               extractors, validator, renderer
    docs/ROSETTA.md          generated flat table (human)
    dist/rosetta.{csv,json}  generated exports (machine)

Splitting *inventory* (mechanical, regenerated) from *mapping* (human
judgement) is what makes upstream releases cheap: a new hashcat version
regenerates one layer and never touches curation.

One file per algorithm rather than one big table is the core
PR-friendliness decision: a contributor touches one small file, merge
conflicts effectively vanish, `git blame` becomes meaningful per algorithm,
and CODEOWNERS can route reviews by path. The flat table people actually
want to read is regenerated on every merge, so nobody loses the spreadsheet
view.

### Sketch of one algorithm file

```yaml
id: ipb2-mybb12
name: IPB2+ / MyBB 1.2+
expression: md5(md5($s).md5($p))
john_dynamic_expr: dynamic=md5(md5($s).md5($p))
category: forums-cms
tools:
  hashcat:  { mode: 2811, verified: vector, verified_at: 2026-08-29,
              verified_with: "v7.1.2-549-g8a15e210b" }
  john:     { cpu: dynamic_12, gpu: null, verified: upstream }
  mdxfind:  { type: MD5-MD5SALTMD5PASS, index: e178, verified: vector }
  crack:    { supported: false }
vectors:
  - hash: "cb5e393cf9d97d19a5d797be77c9ce6a:UhdG"
    pass: rosetta
legacy:
  hashes_org: "IPB / MYBB"
  hashkiller: "IPB2+, MyBB1.2+"
```

Every mapping is tiered — `vector` (round-tripped locally), `upstream`
(asserted by a project that verifies by recomputation), `asserted` (a human
said so), `absent`. This is the feature that makes the reference trustworthy
rather than merely large, and it lets consumers filter to proven rows only.

---

## 4. Validation tooling

Verification is **round-trip cracking**, not string comparison. Both halves
are confirmed working here:

    $ mdxfind -h '^MD5$' -f h_md5.txt -i 1 wl.txt
    MD5x01 482c811da5d5b4bc6d497ffa98491e38:password123

    $ hashcat -m 0 -a 0 --quiet --potfile-disable --self-test-disable h_md5.txt wl.txt
    482c811da5d5b4bc6d497ffa98491e38:password123

Planned scripts:

| Script | Job |
|---|---|
| `extract-hashcat.pl` | `hashcat --hash-info` -> 593 modes w/ category, example hash+pass, slow/deprecated flags |
| `extract-john.pl` | `john --list=format-details` -> labels, algorithm strings, test vectors |
| `extract-mdxfind.pl` | `mdxfind -h` + upstream `HASH_TYPES.md` -> 1001 types, indices, hashcat map, vectors |
| `extract-hashpipe.pl` | upstream `HASH_TYPES.md`; asserts continued identity with mdxfind |
| `validate.pl` | schema; unique ids; every referenced mode/type/label exists in the tool inventory; no orphans |
| `verify-vectors.pl` | the round-trips above; promotes/demotes `verified:` tiers; needs the tools + GPU |
| `render.pl` | -> `docs/ROSETTA.md`, `dist/rosetta.csv`, `dist/rosetta.json` |
| `import-sheet.py` | one-shot migration (Python only for `openpyxl`) |

CI splits into two lanes because they have very different requirements:

- **`validate.pl` + `render.pl`** — pure text, runs on any GitHub runner, gates
  every PR. Fast, no secrets, no hardware.
- **`verify-vectors.pl`** — needs hashcat, John, mdxfind and a GPU. Runs on a
  self-hosted runner on your crack host, on a schedule, not per-PR. It writes
  tier changes back as a PR.

---

## 5. Upstream drift automation

Weekly job on the self-hosted runner:

1. Re-run extractors against current hashcat / John / mdxfind and the two
   upstream `HASH_TYPES.md` files.
2. Diff against committed `data/tools/*.yaml`.
3. If anything changed, open **one PR per upstream**, titled e.g.
   `hashcat 7.2.0: +14 modes, 2 deprecated`, containing:
   - the regenerated inventory,
   - stub `data/algorithms/*.yaml` for genuinely new algorithms, pre-filled
     only with what the machine can prove (mode, example vector, and any
     mdxfind/john_map mapping), everything else blank and labelled
     `needs-review`,
   - a checklist of the human judgement calls required.

The point is that the maintainer's job degrades from "notice hashcat shipped
and go re-research 14 algorithms" to "review a PR". That is the difference
between a reference that stays current and one that reads "Last updated
2023-05-04".

---

## 6. The `Primitives` tab — restart, don't rebuild

The tab's stated goal was "a clear, near-universal meta-language for
expressing algorithms... Suggest starting with JtR's as a base." That goal is
sound and is now *more* achievable than in 2023, because two implementations
exist:

- John: `--format=dynamic='md5(md5($p).$s)'`
- mdxfind: a complete expression compiler — lexer, parser, AST, VM and
  primitive emitters (`hx.lex.c`, `hx.tab.c`, `hx_ast.c`, `hx_compile.c`,
  `hx_vm.c`, `codegen/hx_emit_primitives.c`).

**Recommendation: do not define a third language.** Adopt the hx-style
expression as the canonical `expression:` field, record John's `dynamic=`
form alongside it, and retire the tab. The token table from the tab
(`$p`, `$s`, `trunc`, `utf16le`, `base64`, `rev`, `uc`, `lc`, ...) survives as
documentation of the vocabulary.

Doing this pays off immediately: the expression is a *semantic join key*, so
the validator can assert that hashcat 2811, `dynamic_12` and
`MD5-MD5SALTMD5PASS` genuinely denote the same construction, instead of
trusting that someone lined the columns up correctly.

The `refs` tab becomes `docs/REFERENCES.md`. Its "other suites for potential
inclusion someday" note (Passware, Elcomsoft) should become an explicit
scope decision — see below.

---

## 7. Crack (Alec Muffett)

Add as requested, historical reference only, as `tools.crack` in the schema
and a final column in the rendered table.

Crack 5.0a is unmaintained (last release ~2000) and does not implement hashes
itself — it delegates to the host's `crypt(3)`. So its honest support set is
"whatever libcrypt on the host does", historically `descrypt`, plus
`bigcrypt`/`bsdicrypt` and, on later glibc, `md5crypt` and the SHA-crypts.

That makes it a handful of `true` values against ~1000 `false` ones. Proposal:
render it as a narrow trailing column, populate only the `true` rows, and
document the crypt(3)-delegation caveat once in `docs/REFERENCES.md` rather
than repeating it per row. **Open question for you:** pin it to a specific
Crack release's documented capability, or to "what glibc crypt(3) offers"?
I lean to the former — a frozen historical claim is more useful than one that
drifts with libc.

---

## 8. Phasing

| Phase | Work | Gate |
|---|---|---|
| 0 | Schema + `validate.pl` + `render.pl`, empty data dirs | Schema reviewed |
| 1 | Extractors for hashcat and mdxfind; commit inventories | 593 + 1001 entries land |
| 2 | `import-sheet.py`: 435 curated rows -> per-algorithm files, normalized, junk quarantined | Rendered table matches sheet content |
| 3 | Seed from upstream: mdxfind's 296 hashcat mappings + `john_map.h`'s 125 John rows, tier `upstream` | Coverage jumps; validator clean |
| 4 | John extractor **(blocked, see below)**; close the ~348-format John gap | John inventory lands |
| 5 | `verify-vectors.pl`; promote what round-trips to tier `vector` | Baseline verified % published |
| 6 | Drift automation + self-hosted runner; publish repo | First automated PR opens |
| 7 | Revisit hashpipe once it compiles; revisit Passware/Elcomsoft scope | — |

---

## 9. Blocker

**John cannot be read or executed by the `claude` user.**
`/usr/local/src/sec/crack/john-latest/run/john` and `run/*.conf` are
`0750 royce:royce`, so `--list=format-details` and `dynamic.conf` are both
out of reach; `johnl` reports the binary as "missing or not executable".
Only `src/*.c` is world-readable, and it yields ~114 of ~403 format labels —
not a usable substitute.

Either widen the mode / add a shared group, or run `extract-john.pl` as
`royce` and commit its output. Everything in Phase 4 waits on this; phases
0-3 and 5 do not.

---

## 10. Decisions I need from you

1. **Scope of "algorithm".** Should hashcat's 101 full-disk-encryption modes
   and 35 cryptocurrency wallet modes get first-class rows, or a thinner
   treatment than raw/salted hashes? This drives whether the repo is ~450
   files or ~1200.
2. **Crack column basis** — frozen release capability vs. host crypt(3).
   (I lean frozen; §7.)
3. **Other suites.** The `refs` tab flagged Passware and Elcomsoft. Both are
   closed-source and unverifiable by round-trip. Include as `asserted`-only
   columns, or declare out of scope?
4. **Hash identification.** The 1000-vector corpus would make this repo a
   good backing dataset for hash-ID tooling (`hashID`, Name-That-Hash). In
   scope as an export, or explicitly not our problem?
5. **Repo home** — personal namespace, or offer it to Cynosureprime given how
   much of the verified seed data is theirs? Worth asking them before
   publishing; it also gets the SME review you want built in.
