# cracking-rosetta -- action plan (historical)

<!-- check-numbers: frozen 2026-08-29 -->

Status: **historical record**, frozen as written on 2026-08-29. It was a
proposal then. Most of it has since been built and a few parts were decided
differently, and none of it is maintained: read it for the reasoning that
produced this repository, not for what the repository does today.

`README.md` and `CLAUDE.md` are the current documents. Section 11's design is
restated, with what changed on contact with the code, in `CLAUDE.md` under
"Collisions: when two entries mean the same thing".

Every number below is the survey as measured on 2026-08-29 and is deliberately
not updated. That is what the frozen marker above records, and why
`tools/check-numbers.pl` does not ask this file to date its counts one by one.

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
extra_params` (7). Two more columns -- `Hashkiller-accepted format` and
`hashes.org algo` -- point at services that no longer exist. They still have
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

- `mdxfind/HASH_TYPES.md` and `hashpipe/HASH_TYPES.md` -- a Markdown table of
  every type: index, name, hashcat mode(s), and a complete self-test vector
  as `hash[:salt]:password`. That is 1000 algorithms *with test vectors*,
  which is exactly the corpus needed to verify anything.
- mdxfind ships hashcat mappings for **296 types covering 325 distinct modes**.
- `hashpipe/john_map.h` -- **125 John dynamic formats** mapped to mdxfind
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

    data/tools/*.yaml        GENERATED per-tool inventories -- never hand-edited
    data/algorithms/*.yaml   CURATED, one file per algorithm -- the PR surface
    schema/*.schema.json     validation contract
    tools/*.pl               extractors, validator, renderer
    docs/ROSETTA.md          generated flat table (human)
    dist/rosetta.{csv,json}  generated exports (machine)

Splitting *inventory* (mechanical, regenerated) from *mapping* (human
judgment) is what makes upstream releases cheap: a new hashcat version
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

Every mapping is tiered -- `vector` (round-tripped locally), `upstream`
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

- **`validate.pl` + `render.pl`** -- pure text, runs on any GitHub runner, gates
  every PR. Fast, no secrets, no hardware.
- **`verify-vectors.pl`** -- needs hashcat, John, mdxfind and a GPU. Runs on a
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
     mdxfind/john_map mapping), everything else blank and labeled
     `needs-review`,
   - a checklist of the human judgment calls required.

The point is that the maintainer's job degrades from "notice hashcat shipped
and go re-research 14 algorithms" to "review a PR". That is the difference
between a reference that stays current and one that reads "Last updated
2023-05-04".

---

## 6. The `Primitives` tab -- restart, don't rebuild

The tab's stated goal was "a clear, near-universal meta-language for
expressing algorithms... Suggest starting with JtR's as a base." That goal is
sound and is now *more* achievable than in 2023, because two implementations
exist:

- John: `--format=dynamic='md5(md5($p).$s)'`
- mdxfind: a complete expression compiler -- lexer, parser, AST, VM and
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
scope decision -- see below.

---

## 7. Crack (Alec Muffett)

Add as requested, historical reference only, as `tools.crack` in the schema
and a final column in the rendered table.

Crack 5.0a is unmaintained (last release ~2000) and does not implement hashes
itself -- it delegates to the host's `crypt(3)`. So its honest support set is
"whatever libcrypt on the host does", historically `descrypt`, plus
`bigcrypt`/`bsdicrypt` and, on later glibc, `md5crypt` and the SHA-crypts.

That makes it a handful of `true` values against ~1000 `false` ones. Proposal:
render it as a narrow trailing column, populate only the `true` rows, and
document the crypt(3)-delegation caveat once in `docs/REFERENCES.md` rather
than repeating it per row. **Open question for you:** pin it to a specific
Crack release's documented capability, or to "what glibc crypt(3) offers"?
I lean to the former -- a frozen historical claim is more useful than one that
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
| 7 | Revisit hashpipe once it compiles; revisit Passware/Elcomsoft scope | -- |

---

## 9. Blocker

**John cannot be read or executed by the `claude` user.**
`/usr/local/src/sec/crack/john-latest/run/john` and `run/*.conf` are
`0750 royce:royce`, so `--list=format-details` and `dynamic.conf` are both
out of reach; `johnl` reports the binary as "missing or not executable".
Only `src/*.c` is world-readable, and it yields ~114 of ~403 format labels --
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
2. **Crack column basis** -- frozen release capability vs. host crypt(3).
   (I lean frozen; section 7.)
3. **Other suites.** The `refs` tab flagged Passware and Elcomsoft. Both are
   closed-source and unverifiable by round-trip. Include as `asserted`-only
   columns, or declare out of scope?
4. **Hash identification.** The 1000-vector corpus would make this repo a
   good backing dataset for hash-ID tooling (`hashID`, Name-That-Hash). In
   scope as an export, or explicitly not our problem?
5. **Repo home** -- personal namespace, or offer it to Cynosureprime given how
   much of the verified seed data is theirs? Worth asking them before
   publishing; it also gets the SME review you want built in.

---

## 11. Collisions: how one row should relate to another

Status: **built**, 2026-08-29. Option B was chosen and implemented: the
schema, the emitter, `tools/relate.pl`, four per-entry checks and three
cross-entry checks in `validate.pl`, and a "Same as" column in every rendered
view. Three things below changed on contact with the code and are marked
**[as built]**.

### What went wrong, concretely

Populating `expression:` for 144 entries immediately produced nine expressions
claimed by more than one entry, and `discover-john.pl` found three entries
whose own vectors fall to *different* John formats. Both are the same defect
wearing two hats: **the entry `id` is being asked to carry four independent
facts at once.**

| Axis | Question it answers | Example of it being conflated |
|---|---|---|
| Computation | what bytes in, what bytes out | `joomla` and `md5-pass-salt` are both `md5($p.$s)` |
| Representation | how the digest is written down | `md5` and `md5uc` differ only in hex case |
| Deployment | which product emits it | hashcat mode 11 vs 10; 2611 vs 2711; 21 vs 20 |
| Tool identifier | what to type at a prompt | already many-to-many, already fine |

`md5-md5-plain-salt` is the extreme case: one file, an `aliases:` list naming
four *different* algorithms, and five vectors that fall to three different
dynamics. Nothing in the schema stopped that, because `aliases:` was never
defined as "names for the same computation" -- it was just a search aid.

### Option A -- normalize into two tables

Split `data/algorithms/` into computations (keyed by expression) and
`data/profiles/` for the product-facing rows, each profile pointing at one
computation plus its own modes and vectors.

Cleanest semantics, and the table people read becomes the profile table. But
it is the largest migration, it changes what a pull request touches, and most
entries have no product at all, so several hundred profiles would be 1:1
shells around their computation. Rejected on cost, not on correctness.

### Option B -- one file per entry, explicit typed relations *(chosen)*

Keep the file layout exactly as it is, and make the relationship a first-class
field rather than a hint buried in `aliases:` or prose.

1. **`expression:` is the machine key.** Already populated for 144 entries,
   transcribed from `john --list=subformats`. It is what makes a collision
   detectable at all.

2. **`category:` gets an enum.** The field exists in the schema and is used by
   zero entries; the sheet had a `class` column that was also empty. Revive it
   as the human-intelligible axis:

       primitive | composite | iterated | encoding | application | protocol | kdf

3. **`relations:` -- a typed, many-to-many edge list.**

   ```yaml
   relations:
     - kind: "same-computation"
       entry: "md5-pass-salt"
       distinction: "application"
       note: "hashcat separates these: 11 assumes Joomla's salt, 10 is generic"
   ```

   `kind` says what the relationship *is*:

   | `kind` | Meaning |
   |---|---|
   | `same-computation` | identical bytes in, identical bytes out |
   | `encodes` | same digest, different textual encoding (hex case, base64, tag) |
   | `input-encoding` | same primitive over a re-encoded plaintext (utf16le) |
   | `iterates` | this entry is the other applied N times |
   | `truncates` | this entry is the other, cut short |
   | `collides-on-subset` | agrees only on a degenerate class of inputs |
   | `duplicate-of` | no distinction survives; one of these should go |
   | `covers` | this identifier accepts a SUPERSET of what the other's does |
   | `covered-by` | the mirror of `covers`, and the only asymmetric mirror |

   **`covers` was added 2026-09-08, and it is the vocabulary's only asymmetric
   pair.** Every other kind mirrors to ITSELF and leaves the direction to the
   note; `covers` states its direction in the kind word, so a same-kind mirror
   would put "A covers B" and "B covers A" in the tree at once. It earned
   itself against the WPA family: hashcat 22000 "WPA-PBKDF2-PMKID+EAPOL" and
   22001 "WPA-PMK-PMKID+EAPOL" each accept EITHER a PMKID or an EAPOL
   handshake, where five other rows carry one artifact apiece. Neither
   existing kind states that -- `same-computation` overstates, because the
   covering mode also accepts what the other does not, and
   `collides-on-subset` means the opposite thing, two genuinely DIFFERENT
   computations agreeing on a degenerate class of inputs.
   **It is deliberately NOT in `%JOINS_EXPRESSION`**: `covers` does not assert
   that two entries compute the same thing, so it must never license them to
   share an `expression:`.

   `distinction` says why both rows nonetheless exist:

       application | encoding | input-encoding | iteration | truncation
       | salt-convention | none

   `distinction: none` is only legal with `kind: duplicate-of`, which is how
   a merge gets proposed in data rather than in a comment.

4. **`aliases:` is narrowed to names.** Other spellings of the *same*
   computation, for search. Naming a different algorithm there becomes an
   error, which is exactly the mistake `md5-md5-plain-salt` encodes today.

5. **Optional `application:` / `application_version:`** so "vBulletin >= 3.8.5"
   is data rather than punctuation inside `name:`.

### Option C -- a separate relations file

`data/relations.yaml` holding the whole graph. One place to review, entry
files untouched -- but it moves the fact away from the file that states it, a
contributor editing one algorithm no longer sees it, and every change
collides in a single file. That is the exact failure one-file-per-algorithm
was chosen to avoid. Rejected.

### Why B satisfies both audiences

**Human intelligibility.** Nobody reads a join table. The rendered view stays
one row per entry, with the relation surfaced as a short "same as" column --
`joomla` reads "same computation as md5-pass-salt, differs by application".
`render.pl` can additionally emit Option C's *view* -- a grouped listing keyed
by expression -- without paying Option C's cost, because the edges are data.

**Machine precision.** `dist/rosetta.json` gains a `relations` array. A
consumer building hash-ID tooling can collapse the graph to computations; a
consumer building a cracking cheat-sheet can keep the product rows. Neither
has to guess from a name.

### The rules that make it a gate rather than a suggestion

`validate.pl` grows five checks, and they are what turn the join key into
something enforced:

1. Two entries with an equal `expression` **must** be joined by
   `same-computation`, `encodes` or `duplicate-of` edges. Otherwise: error.
   This is the rule that caught all nine collisions the moment it was
   switched on.

   **[as built]** The check is *connected components*, not every pair. Four
   entries sharing an expression need three edges in a star, not six in a
   clique; requiring the clique makes the data unreadable long before it makes
   it more correct. Equivalence is transitive, so the star says the same thing.
2. Every edge names an existing `id`, and every edge is mirrored on the other
   entry.

   **[as built]** The mirror is *written* by `tools/relate.pl`, not by a
   `--fix` on the gate. `validate.pl` runs on pull requests from forks and its
   verdict is the thing people trust; giving it a flag that edits the data it
   is judging is the wrong shape. The check lives in the gate, the repair
   lives in the tool.
3. `distinction: none` outside `duplicate-of` is an error, and so is a
   `duplicate-of` that claims a distinction.
4. `collides-on-subset` requires a `note` naming the degenerate class -- this
   is where `md5cap`/`md5`, `md5capsha1`/`md5-sha1-pass` and
   `md5-plain-md5-plain`/`md5-pass-md5-salt` are recorded, so the trap is
   documented instead of rediscovered.
5. An entry whose vectors fall to different John formats.

   **[as built]** This one is *not* in `validate.pl` and cannot be: deciding
   it means running a cracker, and the gate must stay a text check that a fork
   PR can run. `discover-john.pl` already reports it under "this entry's
   vectors disagree", and holds the entry back rather than writing the union.

### What the rule cannot see

The collision check fires only where an `expression` exists, and only 144
entries have one -- they are the entries whose John block reached tier
`vector` with identifiers that agree. `oscommerce-xt-commerce` and
`vbulletin-v3-8-5-2` are the same computation as their siblings and have no
expression yet, so nothing forced their edges; they were added by hand. The
gate gets stronger as `expressions.pl` reaches more entries, and it is worth
knowing that its silence is not proof.

### Identifier discipline

`id` remains the stable key and the filename stem, and still never changes
once published -- it is a URL fragment in `docs/index.html` and the key in
`dist/rosetta.csv`. A rename is expressed as a new entry plus a
`duplicate-of` edge and an `aliases:` entry on the survivor, never as an
`mv`.

### The nine collisions under this model

| Entries | `kind` | `distinction` |
|---|---|---|
| `joomla`, `md5-pass-salt`, `ciscoasa` | `same-computation` | `application` |
| `md5`, `md5uc` | `encodes` | `encoding` |
| `md4-utf16-plain`, `ntlmh`, `ntlm-plain-md4-utf16-le-plain` | `duplicate-of` | `none` |
| `ripemd320`, `rmd320` | `duplicate-of` | `none` |
| `md5-salt-md5-pass`, `md5-userid-md5-plain` | `same-computation` | `salt-convention` |
| `md5-md5-pass-salt`, `vbulletin-v3-8-5`, `md5-md5-plain-salt-3`, `md5-capitalise-md5-plain-username` | `same-computation` | `application` |
| `sha1-salt-sha1-salt-sha1-plain-aka-opencart`, `wbb3` | `same-computation` | `application` |
| `sha1-sha1-plain-salt`, `sha1-sha1-plain-substr-plain-0-1` | `same-computation` | `application` |
| `sha256-salt-pass`, `sha256rawsaltpass` | `same-computation` | `encoding` |

Plus, not a collision but the same machinery: `md5cap` ->
`collides-on-subset` -> `md5`, and `md5-plain-md5-plain` ->
`collides-on-subset` -> `md5-pass-md5-salt`.

`md5-md5-plain-salt` and `md5-md5-plain-salt-2` are the one case that needs
splitting rather than linking: their `aliases:` name genuinely different
computations, so each alias becomes its own entry taking the vector that
falls to it, and the originals keep the vector matching their own expression.
**Not done** -- creating entries is a bigger curation act than linking
existing ones, and `discover-john.pl` holds both back and says why.
