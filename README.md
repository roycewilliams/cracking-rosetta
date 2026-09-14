# cracking-rosetta

A cross-reference of password-cracking algorithm identifiers across [hashcat](https://hashcat.net/hashcat/), [John the Ripper](https://www.openwall.com/john/), [mdxfind](https://github.com/Cynosureprime/mdxfind) / [hashpipe](https://github.com/Cynosureprime/hashpipe), and - for historical reference only - Alec Muffett's [Crack](docs/CRACK.md). <!-- counter --> 1547 <!-- endcounter --> algorithms, one file each.

It answers the question you actually have at 2am: this thing is hashcat mode 2811 - what does John call it, and can mdxfind do it?

```yaml
tools:
  hashcat:  { modes: [2811],               verified: vector }
  john:     { cpu: [dynamic_12],           verified: upstream }
  mdxfind:  { types: [MD5-MD5SALTMD5PASS], verified: vector }
```

This is a migration and continuation of the community "rosetta stone" spreadsheet, which had drifted a long way behind its upstreams.

**Were you using the spreadsheet?** The closest equivalent is [`dist/rosetta.csv`](dist/rosetta.csv) - one row per algorithm, one column per tool. Also [`dist/rosetta.json`](dist/rosetta.json) to script against, [`docs/ROSETTA.md`](docs/ROSETTA.md) to just read, and [`docs/index.html`](docs/index.html) to search and filter it in a browser. Every row there has a permalink - the `#` that appears when you hover it - so `index.html#md5-pass-salt` is a link you can paste into an issue, and it is the same id the CSV keys on and the same stem as the file under `data/algorithms/`.

Two things are new since the sheet and worth thirty seconds before you rely on a row. Every mapping now says *how well it is known* - the `*_state` columns carry the tier described below, and `vector` is the only one that means proven. And those three files are **generated**: the source of truth is one small YAML file per algorithm under `data/algorithms/`, which is what pull requests edit, so a correction goes there rather than into a cell.

## Why?

Cross-references like this rot silently, and that's the whole problem. A row that was right in 2021 still *looks* right in 2026 after upstream renamed the format, retired the mode, or changed the salt handling. Nothing in a spreadsheet cell tells you whether anyone ever checked.

So every mapping here carries a tier saying how well it's actually known:

| Tier | Meaning |
|---|---|
| `vector` | This repo cracked the entry's own test vector with that tool, restricted to that exact identifier. **Proven.** |
| `upstream` | Asserted by a project that verifies by recomputation (mdxfind's own type table, hashpipe's `john_map.h`). |
| `asserted` | A human said so. No reproduction on record. |
| `absent` | That tool does not support this algorithm. |

If you're automating against this, filter to `vector` and you're standing on things that have been demonstrated rather than believed. Currently 933 mappings across 653 of the entries.

Nothing is promoted without a round-trip, and - just as important - a failed round-trip never silently demotes anything. A vector that won't crack might mean a wrong mapping, a wrong plaintext, or a missing salt, and the exit status can't tell those apart.

## Be nice

Pull requests are welcome for all of it - the algorithm data, the extractors, the validator, the CI, whatever needs doing.

The one hard rule is mechanical rather than territorial: **don't hand-edit `data/tools/`.** Those inventories are generated from the tools themselves and every one carries a `GENERATED` banner. If a mode or format is missing there, the fix is to re-run the extractor. Same for `vendor/` - refresh it with `tools/fetch-upstream.sh` and commit that separately, so the diff shows what upstream actually changed.

**Keep comments and PR descriptions lean.** Using an LLM to help is fine - but strip the padding before you send it. A wall of generated narrative restating what a three-line diff plainly does costs a reviewer more time than reading the diff would have. Say what changed and why, and stop.

Please don't inflate tiers. `verified: vector` means *this repository cracked the vector*, not "I'm confident". An honest `asserted` with a note saying where the claim came from is far more useful than a hopeful `vector`, and someone will verify and promote it later.

If your source contradicts an entry, don't overwrite it - add your claim in `note` and say so in the PR. Disagreements get settled by verification, not by whoever edited last.

## Howto

1. Regenerate the inventories (only needed when a tool is updated):

```
tools/extract-hashcat.pl --binary /usr/local/bin/hashcat   > data/tools/hashcat.yaml
tools/extract-john.pl    --binary .../john-latest/run/john > data/tools/john.yaml
tools/extract-mdxfind.pl --binary /usr/local/bin/mdxfind \
    --catalog vendor/cynosureprime/hashpipe-HASH_TYPES.md  > data/tools/mdxfind.yaml
```

Each also takes `--from FILE` (or `stdin`), so captured output can be diffed without the binaries present.

2. Check your work:

```
tools/fmt.pl --all              # canonical YAML; also catches a misspelled key
tools/validate.pl --changed     # only reports errors in entries you touched
tools/review-delta.pl           # what your change actually claims
```

`validate.pl` checks entry shape, then resolves every identifier you named against the inventories - whether hashcat mode 2811 exists in *this* hashcat, whether `dynamic_12` is really a CPU format. Naming an identifier no installed tool has is the likeliest defect in a repo like this, and it's exactly what the spreadsheet accumulated over three years. Without `--changed` it reports on everything, which is what CI runs.

3. Prove what you can (needs the tools installed, and a GPU for hashcat):

```
tools/verify-vectors.pl --tool all
```

The tools look for `$JOHN`, `$HASHCAT` and `$MDXFIND` before falling back to the paths this data was generated with, then to `PATH`. An explicit `--john` / `--hashcat` / `--mdxfind` always wins, so a clone on a different machine sets three environment variables once instead of passing a flag every time.

Full instructions: [CONTRIBUTING.md](CONTRIBUTING.md) if you want to add or correct information, [MAINTAINING.md](MAINTAINING.md) if you are reviewing a contribution.

**Looking for something to do?** [`docs/GAPS.md`](docs/GAPS.md) is generated from the data and ranks what is missing by what it costs to fix - starting with the mappings somebody already believes but nobody has ever reproduced, which one command settles, and the entries that need nothing but a test vector, which needs no cracker at all.

**Know one of these formats well?** [`docs/OPEN-QUESTIONS.md`](docs/OPEN-QUESTIONS.md) is the other list: rows where something is known to be odd and the answer needs a person rather than a command - an expression john states but cannot reproduce, a tool that cracks a vector without implementing the algorithm, an entry that may be two algorithms collated into one row. An issue saying what you know is a complete contribution.

**Maintain one of the tools this cross-references?** [`docs/UPSTREAM-FINDINGS.md`](docs/UPSTREAM-FINDINGS.md) is generated from the places where verifying a mapping here turned up something a published document gets wrong - a construction that is not what the type computes, a note that is silent about types running the same code, examples the tool will not read back - plus one measurement that disagrees with a document and is deliberately *not* strong enough to overrule it. Every finding names the version it was measured against, and every one is re-checked on each build against the entry or the type list it came from, so a finding upstream has already fixed fails the build rather than sitting on the page.

**Wondering why some other tool is not a column?** [`docs/OTHER-TOOLS.md`](docs/OTHER-TOOLS.md) is the standing answer, with the measurements behind it: what a column has to earn, why hash *generators* and hash *identifiers* are references rather than columns, and which of the two decisions a license question is currently holding up.

## Layout

```
data/algorithms/*.yaml   curated, one file per algorithm - the PR surface
data/tools/*.yaml        generated inventories - never hand-edited
data/upstream-disagreements.yaml
                         where we knowingly differ from a vendored catalog,
                         executed by tools/check-upstream.pl
data/mdxfind-transcodes.tsv
                         a vector written in an mdxfind type's own
                         serialization, where the stored form cannot be read
                         back - a hint about spelling, still proven before use
schema/                  entry shape, for editors and consumers
tools/                   extractors, validator, verifier, review helpers
vendor/cynosureprime/    vendored upstream catalogs, with provenance
```

Inventory (what each tool supports) is kept apart from mapping (human judgment about which identifiers mean the same thing), so a new hashcat release regenerates one layer and never touches the other.

### For mdxfind's maintainers, and anyone running an mdxfind release

[`dist/mdxfind-corpus.tsv`](dist/mdxfind-corpus.tsv) is this repository's proven vectors written as a regression corpus in mdxfind's own serialization: one row per (type, vector), carrying the type name, the `eN` index, the iteration count, the reader flag, the pepper where there is one, the hash line in the shape the binary reads, and the plaintext that must come back. Every row was reproduced rather than transcribed - `tools/mdxfind-corpus.pl --export` drives the binary for every job and writes only what came back - and `--check` re-runs the file and names anything that stopped reproducing.

The vectors are the cheap part. What the file carries that a catalog does not: which reader flag each type needs, which of the twelve pepper types want the salt field split and which want it whole, and one hash length per run, because mdxfind compares at the length of the shortest hash it loaded and will happily match a truncation.

One file per algorithm rather than one big table is deliberate: you touch one small file, merge conflicts effectively vanish, `git blame` is meaningful per algorithm, and CODEOWNERS can route review by path.

## Notes

* Crack does not get a table column. It attacks two of these algorithms, so a
  column would say "no" on every row but two to buy two rows of information -
  those two are marked (c) and the detail lives in [docs/CRACK.md](docs/CRACK.md).
  The `tools.crack` field is still in the data and in both exports.

* Coverage is partial and visibly so. Run `tools/validate.pl` for live numbers rather than trusting a README - as of 2026-08-29 the inventories held 593 hashcat modes, 552 John formats and 1001 mdxfind types.

* A missing tool column is an open question, not a claim of absence. `absent` is a claim, and it's stated explicitly.

* **`expression` is notation; `john_dynamic_expr` is a command.** The expression column is written in hx notation, which spells a change of representation as a wrapper: `md5(upper(md5($p)))`. John's dynamic compiler spells the same thing as a flavor of the hash function - `md5(MD5($p))` - and rejects the wrapper form as a syntax error. So a row's `john_dynamic_expr` is the string to paste after `john --format=`, and on rows carrying it at tier `vector` that exact string was compiled by John and recovered the row's own plaintext from the row's own hash. Where the two differ they are one claim written twice, not two pieces of evidence.

* **Two tools can agree on the algorithm and disagree about the string.** The `serialization` column says which. `shared` means one test vector here was measured to load in *every* tool that reads anything on this row, so a hash in that form is portable between them. `divergent` means no single string does: the tools split, and a hash in one tool's form has to be re-encoded before another will read it - hashcat writes Kerberos AS-REP as `$krb5asrep$<etype>$<user>$<REALM>$<checksum>$<data>` and John wants the checksum last, and hashcat wants scrypt as `SCRYPT:1024:1:1:...` where John wants `$7$86....NaCl$...`. `unknown` means fewer than two tools have read anything here yet, which is most rows.

* **The native form is the primary one, even where no cracker reads it.** A tool that rewrites a credential to suit its parser has not changed what the credential is, so each vector carries `form:` - `native` for the shape the producing system itself stores or emits, or a tool name for that tool's own spelling. Primacy is derived from that rather than flagged separately: within a group of vectors that are one credential, the native one is primary, and the `primary_form` column says whether a row has one. Empty on a `divergent` row is a live question, and those are in the issue tracker: nothing in a string says what a system stores, so tool forms are set from measurement and `native` is only ever set by a person who knows the system.

* **The practitioner columns say which tool they came from, and that is not decoration.** `hashcat_salted`, `hashcat_speed`, `john_salted`, `john_work_factor` and `mdxfind_salted` are read straight out of the tool inventories, which are regenerated from the binaries, so none of them can drift from the tool. But each is a fact about **one tool's mode**, not about the algorithm: bcrypt is `hashcat_salted: yes` and `mdxfind_salted: no`, because hashcat takes the salt as a salt and mdxfind's `BCRYPT` reads it out of the string. There is deliberately no merged `salted` column, and a `mixed` value means the row's own identifiers for that tool disagree. Nothing here is curated and nothing here carries a tier - these are lookups, not claims.

* **`hash_length` is the length of the string, and `hash_length_basis` says how much that is worth.** `fixed` is two or more vectors that agree; `observed` is a single vector, which is true of what was seen and no more, and is most rows; `varies` means the row's vectors genuinely disagree and both lengths are given - `lm` is 16 or 32 depending on which half you hold. It measures the leading colon-delimited field where that field is entirely hex, so a container format (`$2a$05$...`, a volume header) is empty rather than answered with a number that means something else. `nesting_depth` counts hash applications, not brackets: `md5(upper(md5($p)))` is 2, because `upper()` changes how a digest is written without computing another one.

* No benchmarked speed is published, on purpose. It would be a fact about this one host's GPU and this one build, and it would rot silently the day either changed. hashcat's own `slow` flag gives the distinction you plan around and cannot go stale relative to hashcat.

* The facts behind that column are per test vector, in `data/algorithms/`. `reads_in` lists the tools measured to read that exact string - every tool is run against every vector of a row with every plaintext available, so a tool absent from the list was given the chance and declined. `credential` is the separate, stronger claim that two strings are **one credential written twice**, so nobody reads them as two agreeing pieces of evidence; nothing in the strings can establish that, so a person sets it.

* **The mdxfind iteration count is part of the identity.** `MD5` at `-i 2` is `md5(md5($pass))`, which is John's `dynamic_2`, not `dynamic_0`. The spreadsheet lost these; 17 were recovered by reading mdxfind's own output suffix.

* **mdxfind's hashcat column lists *related* modes, not equivalents.** Type `MD5` names modes 0, 2600, 3500 and 5100 - four different algorithms it reaches by varying `-i` and truncation. Only its 279 one-to-one mappings were seeded; the other 18 are left for a human.

* John is inconsistent about case - `Raw-MD5` on CPU but `raw-MD5-opencl` on GPU. Use the exact label the inventory lists.

* Some John dynamics are switched off by the stock `dynamic_disabled.conf`. They're real formats and valid to reference; `john.yaml` records them separately so this data doesn't depend on one host's config.

* `algorithm_name` in `john.yaml` reports the kernel *this* host built, SIMD width and all, so it can differ between otherwise identical machines. Compare labels and example ciphertexts when looking for real drift.

* Yes, several entries are still named things like `md5-md5-plain-salt-3`. That's what the spreadsheet called them, and renaming an id is a breaking change for anyone automating against it, so they stay until there's a good reason.

## Related work

* The original spreadsheet this replaces: [Hash algorithm rosetta stone](https://docs.google.com/spreadsheets/d/1SBv-oRbXb8OapSD1BSPClPXIfiWOL2oH_zTls4sz1rk/)
* A rules rosetta, same idea for rule syntax: [spreadsheet](https://docs.google.com/spreadsheets/d/1vDQWg-eZplEScs7sF4m3eJCEGq3bmmifHsLGL73n4Ig)
* [hashID type list](https://mattw.io/hashID/types) - identification rather than cross-reference
* [Miloserdov on JtR dynamic expressions](https://miloserdov.org/?p=5960)
* Commercial suites are out of scope for now, being closed-source and unverifiable by round-trip: [Passware](https://support.passware.com/hc/en-us/articles/5373220102423-What-hash-types-are-supported-in-Passware-Kit-), [Elcomsoft](https://www.elcomsoft.com/edpr.html)

## Credits

The verified seed data is [Cynosure Prime](https://github.com/Cynosureprime)'s. mdxfind ships a hashcat mapping for 298 of its types, and hashpipe's `john_map.h` maps 125 John dynamic formats to mdxfind types - each confirmed by recomputation across 9672 harvested vectors, with the rows that wouldn't verify omitted rather than guessed. That practice is the model this repo follows.

The rest came from the spreadsheet this replaces, started on 31 March 2018 and built up over the years since by multiple [HashMob](https://hashmob.net/) members. Most of the algorithms here, and most of the names people actually search for, were entered by someone working a real list who wrote down what they found. The tiers in this repo are not a verdict on that work - they record what has been re-checked since, and the great majority of what has been re-checked has held.

## References

* https://hashcat.net/wiki/doku.php?id=example_hashes
* https://github.com/openwall/john - and `doc/DYNAMIC_EXPRESSIONS` in the jumbo tree
* https://github.com/Cynosureprime/mdxfind
* https://github.com/Cynosureprime/hashpipe

## What you can depend on

If you are scripting against this, these are the promises:

* **An `id` never changes.** It is the filename stem, the URL fragment on the browsable page, and the key in the CSV. When two entries merge, the losing id keeps a row as a *tombstone*: `status` is `merged`, `merged_into` names the survivor, every other column is empty. So a join on an id you saw once will keep resolving, and will tell you where the row went.
* **Read the CSV by header name, not by column position.** Columns get added - `merged_into` was added when the tombstone rule was, `john_dynamic_expr` when the expression turned out not to be runnable as-is, `primary_form` when native forms were distinguished from tool forms, and the practitioner columns (`hashcat_salted` through `hash_length_basis`) when the render layer started deriving them from the tool inventories - and a new one may appear anywhere in the row. Nothing already there gets renamed or removed without a note here.
* **The four tiers are the vocabulary**: `vector`, `upstream`, `asserted`, `absent`. Their meanings are fixed; what changes is which one a given mapping has earned.
* **A tier says what was earned; `match` says what was conceded to earn it.** A round trip is usually byte-exact and then the field is absent, which is the overwhelming majority. Where it is not, the mapping names it, and `dist/rosetta.csv` publishes it as `<tool>_match` beside `<tool>_state` - because `proven` alone reads identically for an exact match and for one that needed a concession, and 29 rows were in that position before the column existed. The vocabulary is fixed like the tiers are: `plaintext-case` (the tool returns a plaintext differing only in case, by construction - MD5LM and Oracle 7 upper-case, and john's `netlm` is the same defect a third time), `plaintext-reserialized` (the tool echoes a re-encoded plaintext rather than the candidate), `hash-transcoded` (the round trip used the type's own spelling of the vector from `data/mdxfind-transcodes.tsv`, because the tool's reader refuses the serialization the entry stores - the two strings are one piece of evidence written twice, never two agreeing vectors). A *truncated* match is deliberately not in that list: a type matching below its own digest width does not denote the algorithm at all, so it earns a `truncates` relation and no mapping.
* **`docs/` and `dist/` are generated** from `data/` on every change. Don't edit them and don't send PRs against them; they'll be overwritten. `data/algorithms/*.yaml` is the source of truth, and `schema/algorithm.schema.json` plus `tools/validate.pl` are its contract. The two exceptions are hand-written and say so in their first lines: [`docs/CRACK.md`](docs/CRACK.md) and [`docs/OTHER-TOOLS.md`](docs/OTHER-TOOLS.md). Everything a renderer writes carries a `GENERATED by` header, so that is the test rather than the directory. `dist/availability.csv` is generated too, but by `tools/availability.pl` from upstream clones rather than by the render workflow, so it is refreshed by hand and not on every change.
* **`data/tools/*.yaml` is a mechanical dump** of what each tool reports, regenerated wholesale when a tool is upgraded. Treat it as upstream's data, not ours. **This repository tracks each tool's upstream tip, not its releases** - the mappings people arrive asking about are the new ones - so an inventory routinely names identifiers a release build does not have.
* **[`dist/availability.csv`](dist/availability.csv) is how you check that against your own build.** One row per (tool, identifier) with the earliest upstream version that carries it, derived from upstream's git history by `tools/availability.pl`. It matters more than it sounds: as of 2026-09-06, 13 of hashcat's 595 modes are in no release at all, and this repository publishes all 13 as proven. Read `first_version` with `first_version_exact` beside it - `no` means the identifier was already present in the oldest version the derivation can see (hashcat's per-mode files begin at v6.0.0) and may be older. `first_version` empty means: in no tagged release yet. It says whether your build will *recognise* an identifier, not whether it computes it correctly. Unlike the rest of `dist/` this file is generated locally rather than in CI, because it needs clones of the upstream repositories; `tools/validate.pl` reports when it has drifted out of step with the inventories. **john is covered as of 2026-09-07, and it is the starkest case in the file**: john's newest jumbo release is `1.9.0-Jumbo-1`, dated 2019-05-14, so 57 of the 402 named formats here are in no release at all - if you installed john from a distribution package, you do not have them. A john format is not a file the way a hashcat mode is, so the derivation is git's pickaxe on the quoted label instead, and it is more cautious as a result: where the label's literal first appears in a tree-wide refactor rather than in one format's own file, `first_version_exact` says `no` and `first_seen_date` is left empty rather than reporting a date that is really the refactor's. An empty `first_version` WITH a `first_seen_date` means "in no release"; both empty means "could not be dated". john's 150 `dynamic_N` labels are not covered at all - they are defined in configuration rather than by a C literal, so the instrument does not reach them.

## License

MIT, for the code **and the data**. See [LICENSE](LICENSE).

The data matters more than the code here, so to be explicit: the YAML entries, the generated CSV/JSON exports and the test vectors are offered under the same MIT terms. Attribution is welcome and the [Credits](#credits) are the people to give it to.

Three questions come up often enough to answer here:

* **The individual facts are not ours to license.** That hashcat mode 2811 is what John calls `dynamic_12` is a fact, and facts do not carry copyright. What MIT covers is the tooling, the schema, the prose, and the selection and arrangement of the whole - the parts that took judgment. Use the mappings however you like; the license is there so everything around them travels too.
* **`data/tools/*.yaml` is upstream's output**, dumped from hashcat, John and mdxfind by the extractors in `tools/`. It is here so the cross-references can be checked against something, not because this project claims it.
* **Database rights, if any, are licensed too.** In jurisdictions recognizing a *sui generis* database right, any such right in this collection is licensed on the same MIT terms, so your permission over the data is your permission over everything else here, including the condition that the notice travels with it.
