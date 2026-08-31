# cracking-rosetta

A cross-reference of password-cracking algorithm identifiers across [hashcat](https://hashcat.net/hashcat/), [John the Ripper](https://www.openwall.com/john/), [mdxfind](https://github.com/Cynosureprime/mdxfind) / [hashpipe](https://github.com/Cynosureprime/hashpipe), and - for historical reference only - Alec Muffett's [Crack](docs/CRACK.md). <!-- counter --> 783 <!-- endcounter --> algorithms, one file each.

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

Full instructions: [CONTRIBUTING.md](CONTRIBUTING.md) if you want to add or correct information, [MAINTAINING.md](MAINTAINING.md) if you are reviewing a contribution.

**Looking for something to do?** [`docs/GAPS.md`](docs/GAPS.md) is generated from the data and ranks what is missing by what it costs to fix - starting with the mappings somebody already believes but nobody has ever reproduced, which one command settles, and the entries that need nothing but a test vector, which needs no cracker at all.

## Layout

```
data/algorithms/*.yaml   curated, one file per algorithm - the PR surface
data/tools/*.yaml        generated inventories - never hand-edited
schema/                  entry shape, for editors and consumers
tools/                   extractors, validator, verifier, review helpers
vendor/cynosureprime/    vendored upstream catalogs, with provenance
```

Inventory (what each tool supports) is kept apart from mapping (human judgement about which identifiers mean the same thing), so a new hashcat release regenerates one layer and never touches the other.

One file per algorithm rather than one big table is deliberate: you touch one small file, merge conflicts effectively vanish, `git blame` is meaningful per algorithm, and CODEOWNERS can route review by path.

## Notes

* Crack does not get a table column. It attacks two of these algorithms, so a
  column would spend 782 rows saying "no" to buy two rows of information -
  those two are marked † and the detail lives in [docs/CRACK.md](docs/CRACK.md).
  The `tools.crack` field is still in the data and in both exports.

* Coverage is partial and visibly so. Run `tools/validate.pl` for live numbers rather than trusting a README - as of 2026-08-29 the inventories held 593 hashcat modes, 552 John formats and 1001 mdxfind types.

* A missing tool column is an open question, not a claim of absence. `absent` is a claim, and it's stated explicitly.

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

## References

* https://hashcat.net/wiki/doku.php?id=example_hashes
* https://github.com/openwall/john - and `doc/DYNAMIC_EXPRESSIONS` in the jumbo tree
* https://github.com/Cynosureprime/mdxfind
* https://github.com/Cynosureprime/hashpipe

## Licence

MIT. See [LICENSE](LICENSE).
