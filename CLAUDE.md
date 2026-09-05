# CLAUDE.md -- cracking-rosetta

Cross-reference ("rosetta stone") of password-cracking algorithm support and
identifiers across hashcat, John the Ripper, mdxfind/hashpipe, and -- for
historical reference only -- Alec Muffett's Crack.

Migrated from a Google Sheet:
`https://docs.google.com/spreadsheets/d/1SBv-oRbXb8OapSD1BSPClPXIfiWOL2oH_zTls4sz1rk`

## Prime directive

**Never assert a mapping that has not been reproduced.** A row saying
"hashcat 2811 == dynamic_12 == MD5-MD5SALTMD5PASS" is only trustworthy if a
test vector was actually cracked by each named tool under that exact
identifier. Unverified mappings are allowed, but must be labeled as such
(see Verification tiers). This mirrors upstream Cynosureprime practice -- see
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

### Two-layer split -- why

`data/tools/` is a mechanical dump of what each tool *actually supports*,
regenerated from the canonical binary. `data/algorithms/` is human judgment:
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
| mdxfind | `/usr/local/bin/mdxfind` (RCS 1.545, 2026-08-29) | `mdxfind -h` |
| hashpipe | `/usr/local/bin/hashpipe` (v1.192, 2026-09-04) | `hashpipe -T` (see `tools/extract-hashpipe.pl`); feed it `hash:plaintext` on stdin, or `TYPE[xNN] hash[:salt]:pass` under `-c` |
| Crack | not present | hand-maintained, frozen |

Upstream, for drift detection and as seed data:

- `github.com/Cynosureprime/mdxfind` -- `HASH_TYPES.md`
- `github.com/Cynosureprime/hashpipe` -- `HASH_TYPES.md`, `john_map.h`

**mdxfind's SOURCE is on this host and outranks every document.**
`/usr/local/src/sec/crack/mdxfind/github/mdxfind`, MIT licensed, kept current
by Royce. `mdxfind.c` carries the per-type implementations and a full RCS
revision log; `hx.l` and `hx.y` are the expression grammar; `hx_func.c` the
primitives. Use it, in this order of authority: **the source, then the binary's
own output, then the hx specification, then `HASH_TYPES.md`.** Appendix A has
been measured wrong about its own types (e308 omits the password operand) and
the published catalogs lag the binary, so a document is the weakest of the
four. Two things the source settles that nothing else does: what a type
actually emits, and WHEN it changed.

**Check the revision log before trusting a vector.** The source can be ahead of
the binary, and a revision can change what a type COMPUTES rather than only how
it is described. Measured 2026-09-02: source 1.545 against binary 1.540, and
revision 1.543 repaired a buffer-layout bug in e607 `SHA1MD5SALTPASSPEPPER` --
the old code hashed the salt followed by a TRUNCATED digest, with output
depending on salt length. Upstream's own note: "any hash cracked as e607 before
this revision will not verify against it." Every `verified: vector` here is a
measurement against the binary of the day, so after an upstream pull, diff the
revision log for behavior changes and re-verify what they touch -- do not
rewrite entries from source while the binary is older than it.

**hashpipe's SOURCE AND BINARY are now on this host too.** The source is
`/usr/local/src/sec/crack/hashpipe`, MIT; the binary is INSTALLED at
`/usr/local/bin/hashpipe` beside hashcat and mdxfind, since 2026-09-04. It
was run out of its working tree before that, and the move is not
housekeeping: rebuilding from a fresh clone that day moved the tree to
`hashpipe.old`, which would have taken the old path with it. Working since
2026-09-02 and at v1.190 (commit `e528d88`) since 2026-09-04. It takes
`hash:plaintext` on stdin and names the type that reproduces it, which makes
it a THIRD independent oracle beside mdxfind and john rather than a document
to be read. The same authority order applies as for mdxfind: source, then
binary, then specification, then `HASH_TYPES.md`.

**All 1026 types now reproduce their own vectors** (`hashpipe -T`, 1026
passed, 0 failed, 2 skipped for the two registered types that ship no
vector). BMW224 and BMW256 failed from 2026-09-03 to 2026-09-04 and that was
never hashpipe: sphlib's `bmw.c` violates strict aliasing and GCC 12+
miscompiles its 32-bit core, so a `libsph.a` built without
`-fno-strict-aliasing` gets BMW224/BMW256 wrong and BMW384/BMW512 right
(upstream `pornin/sphlib` issue 3). A fresh clone built with hashpipe's own
`make deps` -- which passes the flag, `Makefile` line 268 -- fixed it.
**The lesson is the durable part: a self-test failure is evidence about the
BUILD, and only sometimes about the tool.**

**hashpipe is still not a separate column, but the alias rule now has a
measured exception.** Its type list was diffed against the local mdxfind
binary on 2026-08-29: 1000 vs 1001 types, zero name mismatches, zero
hashcat-mode mismatches (mdxfind has one extra index, e426). Names and
hashcat modes still agree. **Iteration suffixes do not.** Measured 2026-09-02,
same hash and same plaintext, each tool pinned to the named type: mdxfind
reports `MD5RAWx02`, `SHA1RAWx02`, `SHA256RAWx02`, `SHA512RAWx02` and
`MD5CAPx02` where hashpipe reports all five at `x01`. The cause is in
mdxfind's source -- `JOB_MD5CAP`'s loop is `for (x = 2; x <= Maxiter; x++)`
with `checkhash` INSIDE it, so mdxfind labels its first emitted value `x02`
and hashpipe labels the same value `x01`. Since the suffix is part of the
identity (see the pitfall below), **this repository follows mdxfind for
`iterations:` and never seeds that field from a hashpipe source.**

**The 25 names hashpipe has and mdxfind does not are TRANSIENT, and that is
upstream's own account.** Waffle told Royce (relayed 2026-09-03) that they
exist because he is improving hashpipe's overlapping support with algorithms
JOHN supports. That is the author's statement of intent, not a measurement,
so it is recorded as such -- but it predicts something checkable, and the
check passes. Measured 2026-09-03 by normalizing each of the 25 names (upper-
case, strip non-alphanumerics -- the separator-drift rule) and looking for it
in `data/tools/john.yaml` and in every identifier `data/algorithms/` publishes
(id, name, aliases, legacy, mdxfind types, john cpu/gpu labels): of the 25,
**15 have a john format, and 13 already reach a row in this repository by an
exact identifier** -- DRAGONFLY3/4-32/64, EPISERVER-SID, GOST94CRYPT, H3C,
IPB2, MONGODB, ORACLE11, POSTOFFICE, RVARY, SUNMD5. Every one of those is
john-supported, which is exactly the overlap he describes.

**So the argument for a fourth column is weaker than it looked, on its own
headline example.** The case put to Royce on 2026-09-02 was that "someone
arriving by MONGODB lands nowhere". They do not: `MONGODB` normalizes onto a
john format the `system-network` entry already carries. Only ONE of the 25 is
unreachable here by any identifier: `QAS-VASAUTH`. Corrected 2026-09-03 --
the first measurement said three, having matched on NAMES alone, but
hashpipe's own `JohnMap[]` states `MD4PASSSALT` = `dynamic_32` and
`MD4SALTPASS` = `dynamic_31`, so both are reachable by a john identifier this
repository already carries. **Ask `john_map.h` before calling a hashpipe type
unreachable**; it is 132 rows of DYNAMICS ONLY -- zero named formats, so it
says nothing about `sunmd5` or `mongodb` -- but on a dynamic it outranks any
name matching. (`MD5PASSSALTMD5PASSSALT` = `dynamic_1505` is in
`JohnMapLocal[]` and stays unusable under the rule above.) One ordinary gap is a
seeding backlog, not a structural case for a new column and a new key in every
entry. Nine more match only as substrings (`SAPCODVNH256` against `SAPCODVNH`,
`SHA512RAWPASSSALT` against `SHA512`) and are NOT established: a substring is
a hint for a curator, never a mapping.

Note what this does and does not settle. It addresses the 25 NAMES only. The
iteration-suffix divergence above is a separate, measured disagreement with
its own record in `data/upstream-disagreements.yaml`, and nothing here
touches it. And because the divergence is transient by upstream's account,
the thing to watch after the next `fetch-upstream.sh` is the list SHRINKING:
if these types arrive in mdxfind, they stop being hashpipe-only and the
question closes itself.

**What detects that it has stopped being true is
`data/upstream-disagreements.yaml`, executed by `tools/check-upstream.pl`.**
Until 2026-09-02 this paragraph named a `tools/extract-hashpipe.pl` that had
never been written, so the documented drift detector was a human remembering
to read a `fetch-upstream.sh` diff. The `mdxfind-catalog-lags-binary` record
now asserts the agreement itself: on every index the vendored catalog and the
local inventory share, the name and the hashcat mapping must be identical,
and the only indices the binary has beyond the catalog are the ones the
record lists. A mismatch is the alias rule expiring.

That record checks names and hashcat modes, and it CANNOT see the suffix --
`HASH_TYPES.md` does not carry one. The `hashpipe-john-map-agreement` record
is what sees it: on every john dynamic that hashpipe's `john_map.h` and this
repository both name, the hashpipe type AND the iteration count must agree,
except for a listed set. It found the numbering split above, and it is the
reason a third record kind exists at all.

**Do not seed from `john_map.h`'s second table.** v1.189 added
`JohnMapLocal[]`, 51 config-defined dynamics; upstream's own comment says the
NUMBERING IS LOCAL to the machine that generated it and the table is for input
only. That is demonstrable here: upstream's `dynamic_1013` is `MD5PASSSALT`
and its `dynamic_1014` is `POSTGRESQL`, while this host's john has the two the
other way round. `check_john_map` reads the first table only, on purpose.

## Verification tiers

Every per-tool mapping carries `verified:`:

- `vector`   -- a test vector was round-tripped locally by that tool under that
               exact identifier. The only tier that means "proven".
- `upstream` -- asserted by an upstream project that verifies by recomputation
               (mdxfind's `Hashcat mode` column, hashpipe's `john_map.h`).
- `asserted` -- a human said so; no reproduction on record.
- `absent`   -- that tool does not support this algorithm.

Also record `verified_at` (ISO date) and `verified_with` (tool version string).
Never promote a tier without re-running the check.

The same four tiers apply to `expression:` via `expression_proof:` -- see
**Expression language** below. It is the same kind of claim and deserves the
same audit trail.

### `absent` is a measurement, and it expires

The other three tiers describe a claim that was proved. `absent` describes one
that could not be, which makes it the only tier that can go wrong while nobody
touches it: it is a statement about a BUILD, and the build moves.

Measured 2026-09-05. Every one of the 343 mdxfind absences here had been
established against mdxfind RCS 1.545 with 1002 types, by a full
`discover-mdxfind.pl` sweep with positive controls -- careful work, correctly
recorded. `data/tools/mdxfind.yaml` had since been regenerated at RCS 1.576
with 1027. The 25 indices added between the two builds, `e1003`-`e1027`, are
overwhelmingly John-shaped formats, and nineteen of the absences were about
exactly those algorithms. The notes even said so, in terms: *"hashpipe DOES
cover this algorithm, as type DRAGONFLY3-32, which mdxfind has no equivalent
of ... This is the absence of an IDENTIFIER, not of the algorithm: if mdxfind
gains one, this becomes a mapping."* mdxfind gained one. Nothing compared the
two version strings, so nothing noticed, and the rows went on saying no.

So **`verified_with` on an `absent` claim is load-bearing, not decoration.**
`validate.pl` now reports every absence naming a build the inventory has moved
past -- an advisory, because a stale absence is unverified rather than wrong.
It found 327 mdxfind claims still at 1.545 and 19 hashcat claims with no
recorded build at all, which cannot be checked even in principle.
`verify-vectors.pl` wrote a bare `"mdxfind"` into the same field and now writes
the inventory's version string, so what it promotes stays auditable.

What closes an absence is cheap, and should be the reflex after any inventory
refresh: sweep the corpus against the indices the refresh ADDED, one type per
invocation, rather than re-running everything. Measured 2026-09-05: 25 types
over 1761 hashes took under a minute.

A GAPS.md section per tool is the other half. Only hashcat had one, so the 25
new mdxfind types were in no queue and nobody had reason to look at them.

### An entry with no vector is not always a gap

`GAPS.md` used to list every entry with no `vectors:` under "No test vector at
all", and tell the reader that supplying one "is the whole contribution".
`OPEN-QUESTIONS.md` listed the same set under "Entries nothing can prove yet".
Both were generated from one predicate -- the entry has no vectors -- which
cannot see the difference between a backlog and a settled fact.

For `parallel` the request was unanswerable. mdxfind's `JOB_PARALLEL` case is
`hashcnt += Maxiter; break;`: it advances the hash counter and returns,
computing no digest and calling no `checkhash`. There is no hash for any
plaintext to produce, which is also why e426 is the one index mdxfind has that
hashpipe does not -- there is nothing there to implement. Upstream had already
established this and it was recorded in the entry's `notes:`, in prose, where
no generator could read it, so both documents went on asking.

So the reason is data. `no_vector:` carries a `reason:`, a required `note:`
and the usual `measured_at`/`measured_with`, and the vocabulary is exactly two
values that are NOT degrees of one thing:

- `impossible` -- no vector can exist. The type emits nothing, so nobody can
                  supply one however well equipped. Not a question.
- `withheld`   -- a vector exists, and storing it under the row as written
                  would assert something false. `sha1saltcx` is the case: the
                  only published example is a ten-iteration hash and the row
                  declares no iteration count, which the schema reads as one.
                  What is missing is a curator's decision, not a contributor's
                  data.

Deliberately not a fifth tier. Tiers say how well a claim is known and can be
promoted; this says why a claim will never be made, and nothing about it is
promoted. `validate.pl` refuses it beside `vectors:` -- a vector arriving is
the good outcome and must not leave a stale denial standing next to the thing
it denies -- refuses an unknown `reason:`, and refuses a missing `note:`,
because an unexplained `impossible` is indistinguishable from a shrug and
forecloses the question it claims to settle. It is also on the tombstone
forbidden list: a tombstone asserts nothing, and this is an assertion.

`render.pl` then routes rather than hides. The `impossible` ones appear under
`OPEN-QUESTIONS.md`'s "What is deliberately not a question", derived so that
marking another type stops it being asked for without anyone editing a list;
the `withheld` ones get their own section stating the decision that is owed;
and `GAPS.md` says how many it set aside and why, so the count shrinking is
visible rather than silent.

One trap worth keeping, because it was nearly shipped: the row hash in
`render.pl` IS the export shape -- `dist/rosetta.json` serializes it whole --
so carrying `no_vector` there for a document's benefit put `"no_vector": null`
on every row and widened the published contract without anyone deciding to.
It lives in a lookup beside the rows instead. **Anything added to that hash is
published; check `git diff dist/` before believing a render is clean.**

### And a mapping with a vector beside it is not always one command away

The same defect one level down, and it survived the fix above because it is a
different predicate. `GAPS.md` section 1 ranks a claimed-but-unproven mapping
as the cheapest contribution in the repository -- the identifier and the vector
are both already on the row, so "one command decides it" -- and selects on
`state eq 'claimed' && $r->{vecs}`. It cannot see whether the command CAN
decide.

`md5specam` is the case, and note that it was ALREADY correct about everything
except the queue it sat in. mdxfind and hashpipe do not compute the same thing
under that name: hashpipe's `compute_md5specam` is `md5($p . md5_raw($p))` and
takes neither salt nor user, while mdxfind's `JOB_MD5SPECAM` reads a userid off
the line and breaks out when that field is empty. The row's vector is
hashpipe's. Pinned with `-h '^MD5SPECAM$'`, mdxfind performs ZERO hash
calculations on it under `-f` and zero again under `-F` with a userid appended
-- it declines the input shape rather than computing and missing -- so a
failure to crack is not evidence against the mapping, and the tier correctly
stayed at `asserted`. What was wrong was advertising it as a one-liner.

So `tools.<tool>.no_round_trip:` says that this ENTRY's vectors cannot exercise
that TOOL's identifier, with the same `reason:` + required `note:` +
`measured_at`/`measured_with` shape. Two reasons: `different-algorithm` (the
tool computes something else under that identifier) and `emits-nothing` (the
tool's type produces no digest for any input). It is scoped deliberately: it
says nothing about whether the tool could round-trip some OTHER vector, and it
never changes the tier, which stays whatever the evidence supports.

`validate.pl` refuses it at tier `vector` -- the round trip demonstrably
happened, so the block is stale -- and at tier `absent`, where there is no
mapping for a vector to promote and nothing to explain. `render.pl` moves the
pair out of `GAPS.md` section 1 and into `OPEN-QUESTIONS.md` under "Mappings
this row's vector cannot settle", because the question that IS open is a
curator's: does that identifier belong on this row at all, or does it want a
row of its own.

Note the shape this shares with `no_vector:` above, since a third instance
will want the same treatment: **a queue that selects on the absence of
evidence will keep proposing work that has already been done.** Both fixes
record the measurement that closed the question, in a field a generator can
read, and let the queue subtract it.

## Round-trip verification recipes

These are proven working in this environment.

    # hashcat  (GPU present: RTX 4060 Ti; nvmlInit warning is benign)
    hashcat -m <mode> -a 0 --quiet --potfile-disable --self-test-disable \
        <hashfile> <wordlist>

    # mdxfind  -- pin the type; -i 1 unless the type is iterated
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
  **But HALF of mdxfind's report lines carry no suffix at all, and they are
  not junk.** The print is guarded by `if (x > 0)` in every emitter
  (`mdxfind.c` around lines 10264-10703): a type whose internal iteration
  counter never leaves zero prints its bare name. The value is not lost --
  the same block tallies at `TOTALFOUND(op)[x > 0 ? x - 1 : 0]` and the
  end-of-run summary prints slot 0 as `x01` -- so **a bare line IS the first
  iteration, stated by the binary in its own totals.** Measured 2026-09-03:
  235 of 1152 report lines in a full sweep are bare, covering 163 entries,
  141 of which appear NO other way. `absence.pl` and `discover-mdxfind.pl`
  both required the suffix and were one `--apply` from publishing 13 entries
  as "mdxfind has no type for this" when a type had just cracked them.
  `mdxfind-corpus.pl` and `verify-vectors.pl` already read `(?:x(\d+))?`.
  No type in the inventory ends in `x<digits>`, so stripping a trailing
  suffix cannot eat a name.
  **`hashpipe -c` re-admitted this exact error twice, and is now clean.**
  v1.190 added `-c`, which verifies each line against its own leading
  `TYPE[xNN]` label and runs no detection -- a per-line TYPE PIN, the
  equivalent of `mdxfind -h '^TYPE$'`. The type half was strict from the
  start, measured against negative controls 2026-09-04: a wrong type, a
  wrong plaintext and an unknown label are all refused, the last fatally.
  The SUFFIX half took two fixes. In v1.190 a depth-1 match verified under
  any labeled depth, so `MD5x05` accepted `md5($p)`; v1.191 closed that per
  line and left it standing in a BATCH, where a line's plaintext could still
  claim ANOTHER line's digest -- `MD5x02 <md5^2>` beside `MD5x03 <md5^1>`
  verified both, the second emitted as `MD5x01`. v1.192 closed that too.
  Measured 2026-09-04 on v1.192: every off-diagonal cell of md5^1..md5^5 is
  refused, and that batch verifies the `x02` line and refuses the `x03` one.
  **The reading traps are NOT version history and still apply in full.**
  `-c` writes a VERIFIED line to stdout, relabelled with the depth that
  actually matched, and echoes a REFUSED line to stderr VERBATIM. So:

  - **Compare the emitted suffix with the one you asked for.** Never treat a
    line on stdout as agreement. This is what caught both leaks.
  - **Never read `-c` with the streams merged.** `echo 'MD5x03
    <md5^1>:password' | hashpipe -c` prints the line straight back and looks
    like a pass; on v1.190 it was one and on v1.191 it was the refusal echo,
    and the command cannot tell you which. Use `2>/dev/null`, then a
    positive control that must still print.
  - **In a batch, output lines do not correspond one-to-one with input
    lines**, since refusals go to the other stream. Match on the emitted
    HASH, never on position.
  - The emitted label is BARE where the input was bare or `x01`, the same
    convention as mdxfind's bare lines.

  **`tools/test-hashpipe-c.pl` measured all of it, and is why both fixes
  were confirmed on the day they landed** rather than by someone remembering
  to re-check. It asserts the CURRENT behavior on purpose, holes included,
  so a fix FAILS it and the failure text says what to do -- which is what
  happened at 1.191 and again at 1.192. It now also carries the opposite
  control, correctly-labeled multi-line batches at mixed depths: a `-c`
  that refused too much would satisfy the leak assertions exactly as a
  correct fix does, and without those "the leak is gone" and "the batch path
  is broken" are the same reading. It needs a hashpipe binary, so it is not
  in CI -- `validate.yml` deliberately runs no cracker -- and it skips
  loudly rather than silently when one is absent.
  Worth knowing how the original report landed, because it nearly did not:
  "by design" came back first, on a demonstration that `MD5x03` rejects an
  md5^4 digest -- which is true, and is a cell the hole does not touch. It
  took the same file plus ONE line, `MD5x03` against md5^1, to separate the
  two claims. **A refutation aimed at a different cell of the matrix is not
  a refutation**; show the cell. Both later readings of this flag went wrong
  the same way, in the other direction -- a merged-stream one-liner, which
  is consistent with a pass AND with a refusal -- which is why that is now
  the second bullet above rather than a footnote here.
  **And `-c` numbers iterations mdxfind's way while the detect path does
  not**: same binary, same hash, re-measured on v1.192, `-c` says
  `MD5CAPx02` where plain stdin detection says `MD5CAPx01`. So hashpipe
  carries two numberings, and `data/upstream-disagreements.yaml` still
  records the detect path's -- which is the one this repository uses as its
  hashpipe oracle. `test-hashpipe-c.pl` asserts that split too.
- **A shared salt pool can MANUFACTURE a hit, not only suppress one.** The
  entry above records that a large type selection suppresses matches. The
  mirror image is real, measured 2026-09-05: sweeping 1761 corpus hashes with
  `mdxfind -M e1003 -F <all>` reported a hit on the `md4` row, because with
  every corpus salt loaded `MD4SALTPASS` finds a salt for which `md4($s.$p)`
  equals `md4($p)` -- the empty one. Pinned to that row's own vector alone,
  the same type cracks nothing. Four more hits in the same sweep had the same
  shape: `SHA512RAWPASSSALT` on two `SHA512PASSSALT` rows, which are identical
  at x01 and differ only in iteration role, and `SHA1UCUSERPASS` on `MANGOS`.
  Every one was on a row already naming a LOWER `eN`, which is the existing
  tie-break doing its job. **A corpus-wide sweep proposes; a run pinned to the
  single row disposes.** Never record a mapping from the sweep line.
- **hashpipe's `-m` does not restrict what a recognised wrapper reaches.**
  Measured on hashpipe RCS 1.193, 2026-09-05, and reported upstream rather
  than worked around here. `parse_line`'s prefix recogniser resolves a known
  wrapper with `find_type_by_name("7ZIP")` and never consults `ModeList`, so
  `printf '$7z$...' | hashpipe -m e1021` reports `7ZIP` although e1021 is
  DRAGONFLY3-32. 61 types are named by a recogniser call site; over a
  1743-line corpus with a 29-index `-m`, 96 of 122 results named a type
  outside the selection. Types with no recogniser entry -- MONGODB, H3C,
  DRAGONFLY3-32, SUNMD5, ORACLE11 -- obey `-m` correctly, which is the
  control. So a `-m` pin is not yet the hashpipe equivalent of
  `mdxfind -h '^TYPE$'`, and a tool treating it as one will record a mapping
  the pin never proved.
- **hashpipe loses matches as the thread count rises.** Same input, same
  flags, five runs each, measured 2026-09-05: `-t 1` and `-t 2` give 122 every
  time, `-t 4` gives 116, `-t 8` gives 117, `-t 16` gives 114-119 varying run
  to run. The default is the CPU count. A lost match is indistinguishable from
  a genuine negative, which is the failure `absence.pl` exists to prevent, so
  run hashpipe at `-t 1` wherever its silence will be read as evidence.
- **Name separator drift.** The source sheet wrote `HAV128_4` where mdxfind
  writes `HAV128-4`. Normalize by stripping non-alphanumerics before matching;
  store the tool's exact spelling.
- **Upstream can name modes that do not exist.** mdxfind's map references
  hashcat modes `11780`, `46100`, `67000`, none of which exist in hashcat
  v7.1.2-549. Report, do not silently drop.
- **Scraped tool output can be elided.** `hashcat --hash-info` truncates a
  long example hash to `48435058...00000 [Truncated, use --mach for full
  length]`, and 181 of 593 modes were recorded that way before anyone tried
  to use one -- hashcat refuses its own truncated example, so those modes
  could not be round-tripped and nothing in the data said why.
  `extract-hashcat.pl` reads `--hash-info --machine-readable` for that
  reason. Check for an elision marker before trusting a scraped field.
  **john elides too, and silently, at 896 characters.**
  `john --list=format-details` truncates `example_ciphertext` to 896
  characters with no marker at all; `--list=format-all-details` gives the same
  field away by labeling it "Example ciphertext (truncated here)". 46 of this
  build's 552 formats are affected, and EVERY container format is, because
  their examples are whole volume headers. Measured 2026-09-01. The failure is
  worse than hashcat's because there is no marker: `diskcryptor` carried a note
  blaming the ~819 candidate plaintexts harvested from john's source for not
  containing the answer, when no wordlist could have cracked a header that was
  never a loadable hash. **When a john example will not load, check its length
  against 896 before concluding anything about the plaintext.** The full hash
  is in john's own `src/*_fmt_plug.c` test array; the rule that the source
  PROPOSES and john's crack PROVES still applies to the plaintext.
  **`tools/seed-john-vectors.pl` is the answer to this, and it reads the
  STRUCT rather than the file.** A first pass that scanned for
  `#define FORMAT_LABEL` missed every format in `haval_fmt_plug.c`,
  `ripemd_fmt_plug.c` and `truecrypt_fmt_plug.c`, because a file defining
  several formats writes each label as a STRING LITERAL in its own `fmt_main`.
  And the array is often not in that file at all: john keeps a container
  format's tests in `<name>_common_plug.c`, and `wpapsk_fmt_plug.c` takes its
  `tests` from the `wpapsk.h` it includes. So the label and the array
  identifier are both read off the `fmt_main` params block, and the identifier
  is resolved through the file's own `#include`s. `#if` is NOT evaluated, so a
  conditionally compiled array yields the UNION of its branches -- `wpapsk.h`
  has one `tests` whose `#ifdef WPAPMK` half carries PMK plaintexts -- which is
  safe ONLY because john is the oracle and a pair from the wrong branch simply
  fails to crack.
- **Two john behaviours are indistinguishable from "did not crack" once the
  output is discarded, and both were.** Measured 2026-09-04.
  **The encoding refusal.** `john.c` line 930 refuses a format flagged
  `FMT_UNICODE` but not `FMT_ENC` unless the encoding is raw or ISO-8859-1,
  and this host's `john.conf` sets `DefaultEncoding = UTF-8` (line 274). It
  prints one line on STDERR and exits; nothing is cracked. `dynamic_1507`
  passes its own `--test=0` and cracks its own published vector the moment
  `--input-encoding=iso-8859-1` is named. So a john job's stderr must be KEPT.
  The retry is legitimate only where the plaintext is pure ASCII, since there
  the two encodings feed the format identical bytes; on anything else the flag
  would make the crack a claim about a different string. A refusal that
  survives the flag is a FAILED job, not a zero: treating it as "ran and found
  nothing" strikes john from `reads_in` on evidence never gathered.
  **The case-insensitive plaintext.** john returns the plaintext it actually
  found, and for a format without `FMT_CASE` that is not the string the
  wordlist held: `netlm`'s own test array says `hiyagerge` and `john --show`
  says `HIYAGERGE`. A byte-equal comparison reads that as a failure, which is
  why `LM`, `netlm` and their neighbours sat unverified while every one of
  them cracks its own vector on the first try. `FMT_CASE` is bit 0 of
  `formats.h`, SET when the format IS case-sensitive, and it is carried in
  `data/tools/john.yaml` as `flags`. Relax on case ONLY where john says the
  bit is clear, and never on anything else.
  **What is NOT one of these is a TRUNCATING format.** `nethalflm` takes seven
  characters and returns `G3RG3P0` for john's own `G3RG3P00!`. The vector is
  upstream's and correct; the strict comparison is also correct; they answer
  different questions and the strict one is the one that gates a tier.
- **Many hashcat modes do not compare the whole digest, so a crack is not
  automatically proof.** Measured on v7.1.2-549-g8a15e210b, 2026-08-31: `-m
  100` accepts any 40-hex string whose LAST 128 bits match `sha1($p)` --
  `deadbeefe046af0e12d3c38472792cd5f081c39f` "cracks" to `rosetta` although
  `sha1("rosetta")` begins `d21af7ec`. `-m 0` compares all four MD5 words, so
  this is per-mode, not universal; 22 of the 44 modes that scored a hit in the
  first full discovery sweep skip a word. It is the SHA-family kernels'
  reversal of the final round, and hashcat also INDEXES its target list by the
  words it compares, so several hashes that differ only there collapse to one
  entry and only one of them is ever reported cracked.
  This is only fatal where the corpus holds a hash DELIBERATELY related to a
  true digest, which is precisely what mdxfind's masked and truncated families
  are: `-m 100` duly "cracked" `SHA1lsb35`, `and(sha1($p), 0x00000fff..ff)`.
  `discover-hashcat.pl` challenges every mode that scores a hit with
  one-character mutants of the digests it cracked, learns which positions it
  skips, and withholds a claim wherever two different corpus hashes are
  indistinguishable under it. Do not record a hashcat mapping for a truncated,
  masked or re-prefixed digest without that check or an independent
  recomputation.
  **The withholding rule is CORPUS-dependent and can fail to fire.** It needs
  TWO hashes in the target set that the mode cannot tell apart; once the
  colliding partner is mapped, it leaves the target set and the survivor is
  proposed with nothing withheld. Measured 2026-09-01: a re-run listed
  `sha1lsb35 <- -m 100` as applicable, although that entry already carries
  `hashcat: verified: absent` recording that the 2026-08-31 canary withheld
  exactly that claim, and although the canary re-measured -m 100 as skipping
  positions 0-7 in the same run. The same run proposed `md5cap <- -m 2600`,
  another already-modeled trap. So the canary is a guard, not THE guard:
  **never run `discover-hashcat.pl --apply` without reading its applicable
  list against the entries it names.**
- **john has the same defect, at its own widths.** `Raw-SHA1-Linkedin` reads a
  leak whose hashes have their leading nibbles zeroed and so ignores hash
  positions **0-4** -- the 20 bits that were zeroed, measured position by
  position 2026-09-01. It is NOT 0-7; that is hashcat `-m 100`'s width and was
  carried across by assumption for a while. `Raw-SHA1` and `dynamic_26` compare
  the whole digest. `discover-john.pl` now carries the same canary, and
  `--mirror-gpu` skips it on purpose because a GPU mirror of an already-named
  CPU format adds no algorithmic claim. `discover-mdxfind.pl` has no canary;
  mdxfind matches on a full raw digest, so it is lower risk, but nobody has
  measured it.
- **A SWEEP'S SILENCE IS WEAKER EVIDENCE THE BIGGER ITS CORPUS AND ITS TYPE
  SELECTION ARE.** mdxfind can fail to reproduce a vector under `-m` over a
  RANGE that it reproduces in one second under `-h` pinned to the same type,
  against the same corpus and the same wordlist. Measured 2026-09-04 on
  YESCRYPT: pinned, mdxfind reports "found 1 unique salts" and cracks both of
  the entry's vectors; selected as part of `e951-e1000` it reports "found 96
  unique salts" and finds nothing. The salt pool is the union over every type
  in the selection, and a large one suppresses the match.
  The effect is ordered and it is large. Three sweeps of the same 1002 types
  on the same day: the full corpus (1668 lines, 485 salted) found a set; a
  LEAN corpus (`--lean --untyped`: the target vectors plus one already-proven
  vector per hash shape, 466 lines, 43 salted) found EIGHT more in 21.5
  seconds; the same lean corpus at `--chunk 1`, one invocation per type, found
  THIRTEEN more again in 917 seconds. Twenty-one mappings the coarsest sweep
  missed.
  **Not one of the twenty-one was ever published as `absent`** -- every one
  was held back by `absence.pl`'s hashpipe corroboration or its name-match
  veto. That is what those two rules are FOR, and it is now a measurement
  rather than an argument.
  So: run more than one sweep, union the chunk files per range, and point
  `absence.pl` at the union. It counts the runs itself -- mdxfind prints
  "Minimum hash length is N characters" once per invocation -- reports the
  number, says what to do when it is one, and writes the count into the claim
  it publishes.
- **A canary must never mutate a base64 digest.** The mutation is defined on
  TEXT and the claim is about a DIGEST, and those coincide only where the text
  IS the digest. Measured 2026-09-01: challenging john's `Raw-SHA1` reported
  that it ignores position 31 of `{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=`. It does
  not -- 27 base64 characters carry 162 bits and SHA-1 is 160, so the last
  character's bottom two bits encode nothing and the mutant decodes to the same
  digest. Both discovery tools therefore mutate only a leading run of at least
  16 hex characters and report anything else as **unmeasured** rather than
  clean. The error is one-directional: a bogus ignored position can only ever
  WITHHOLD a claim, never invent one, so a stale cached verdict costs coverage
  and not correctness.
- **The vendored mdxfind catalog renders SOME types' example digests in
  uppercase hex**, and mdxfind will not read them back that way. Only
  `MD5UCBASE64SHA1RAW` turned out to be purely a case problem; `MD5UC`,
  `SHA256UC` and `RACF` reproduce in neither case. Re-casing on failure is a
  search for something that passes, not a fix -- confirm with `mdxfind -z`
  first, and say so in the entry.
  **Do not type the count here.** This line used to say 15 and that figure is
  not reproducible: measured 2026-09-03, the leading-digest rule -- first
  colon-delimited field, entirely hex, has an upper-case letter and no
  lower-case one -- gives 12 on the vendored hashpipe catalog and 10 on
  mdxfind's own `HASH_TYPES.md`, and widening it to the whole hash portion
  gives 16 and 12. `docs/UPSTREAM-FINDINGS.md` DERIVES the list from the
  vendored catalog on every build and states the rule beside it, so the number
  cannot go stale again. Read it there.
- **A PEPPER type cannot be verified from its vector alone, and the catalog
  hides the pepper in the salt field.** A pepper is a site-wide secret that
  appears in no hash and cannot be derived from one; hx makes it a BUILT-IN
  VARIABLE alongside `pass`, `salt`, `salt2` (`hx.y` line 19), fed to the VM in
  its own slot. mdxfind reads it from a file: `-j` is the global pepper array,
  `-P` the per-type set named by a preceding `-M`. `HASH_TYPES.md` writes it as
  the SECOND space-separated field of the salt --
  `<hash>:<salt> <pepper>:<plaintext>` -- which `-F` alone parses as one long
  salt, so the pepper never reaches the array and the type computes nothing it
  can match. Twelve entries sat at tier `upstream` for that reason on
  2026-09-02: not a wrong vector, an unaskable question. All twelve reach
  `vector` once the field is split and the pepper passed through `-j`.
  **But the split is not universal and the flags do not say which.**
  `SHA1-SALT-UTF16-PEPPER` and `SHA1SALTMD5PASSPEPPER` both carry flags
  `f,s,j` and need OPPOSITE handling: the first has a built-in salt of
  `"f5g= of8="` in mdxfind's `default_salts[]` table, one string the type
  splits itself, so splitting the field BREAKS a vector that was verifying.
  `verify-vectors.pl` therefore keeps the whole-field run primary and tries the
  split only after it finds nothing, which makes a regression structurally
  impossible. That is not the re-casing pitfall below: the hash and the
  plaintext are fixed and only the plumbing varies, where re-casing searches
  for a variant STRING that passes.
- **An upstream catalog can be stale in a way that looks like our error.**
  mdxfind 1.543 changed what e607 computes; the vendored hashpipe
  `HASH_TYPES.md` (commit `81c3b8f`, fetched 2026-08-29) still published the
  PRE-FIX digest `786aab53...` on 2026-09-02, and this repository had seeded it
  and correctly recorded that the local round-trip failed. Do not "fix" our
  side when a published example will not verify: establish the construction
  from source, recompute independently, and check the recomputation against the
  binary. All three agreed here, which is what made replacing upstream's own
  example defensible.
  **The disagreement that leaves behind is now a RECORD, not a note.**
  `data/upstream-disagreements.yaml` holds each place this repository
  knowingly disagrees with a vendored document, and `tools/check-upstream.pl`
  fails three ways: upstream moved, our side was re-seeded back to upstream's
  value, or the two CONVERGED and the record is spent and should be deleted.
  The third is the one nothing could previously detect -- it looked exactly
  like nothing having happened -- and it is what makes a re-fetch that changes
  nothing a passing test rather than an absence of evidence. So: **never
  re-seed `data/algorithms/` from a catalog without reading the register
  first**, and when a disagreement is established, add a record rather than
  only a sentence in the entry's `notes:`. Keep it short -- two records that
  are checked beat twenty that are asserted.
- **Sheet-era junk.** `NOTSUPPORTED`, `MD5AUTOMATICPARTIALMATCH` and
  `MD5UCWITHI2MD5UCX2` appear in the mdxfind column but are not types.
  `WLR1` was on that list and should not have been: it is `WRL1`
  (Whirlpool-1) with the letters transposed, and both mdxfind pinned to
  `WRL1` and john's `whirlpool1` reproduce the sheet's vector. Check a
  suspected non-type against the inventory before writing it off.
- **`--field-separator-char` governs READING, not just printing.** It is how
  john splits LOGIN from HASH on the way in, so setting it to tab makes john
  treat a whole `USER::DOMAIN:challenge:response:blob` line as one login and
  answer "No password hashes loaded" -- which is indistinguishable from a
  format that did not crack, and is how netntlmv2 sat at tier `asserted` while
  its mapping was fine. Measured 2026-09-01. The flag exists for a real reason
  (a vector that contains a colon is otherwise truncated), and `verify-vectors.pl`
  and `discover-john.pl` use it correctly by writing a synthetic login and a
  TAB before each hash. That scheme cannot work for a format whose ciphertext
  EMBEDS its own login -- NETNTLMv2, NETLMv2 and the other challenge-response
  formats -- because displacing that field is exactly what breaks the parse.
  Such a format has to be handed to john natively. `tools/probe-gpu.pl` does.
- **`--show` does not always put the plaintext last.** Where the format has no
  login field john appends it (`$SHA512$abc...:rosetta`); where it has one, john
  re-inserts it into the original line structure instead
  (`TESTWORKGROUP\NTlmv2:password::1122...:blob`). A checker anchored on the end
  of the line silently misses a real crack. Match a whole colon-delimited FIELD.
- **Some tool serializations of one credential genuinely differ, and a
  transcode must be PROVEN, not assumed.** john reads both NTLMv2 spellings,
  but for Kerberos AS-REP hashcat writes
  `$krb5asrep$<et>$<user>$<REALM>$<checksum>$<data>` and john wants
  `$krb5asrep$<et>$<REALM><user>$<data>$<checksum>` -- the checksum moves to the
  END. A transcode that kept it where hashcat puts it produced a string of
  exactly the right shape that john refused to load. Hand the transcoded string
  to john with ONLY the plaintext the original vector states: a wrong rule
  fails to load or fails to crack. And say in the entry that the two strings are
  ONE piece of evidence written twice, or a later reader counts two agreeing
  vectors as corroboration.
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

The expression is the semantic join key -- it is what lets a validator assert
that two tools' identifiers really do denote the same thing.

`tools/expressions.pl` populates both fields from `john --list=subformats`,
which states what each of john's dynamics computes in the syntax
`--format=dynamic='...'` takes back. It writes only where the john block
reached tier `vector` and every identifier that block names prints the same
expression, so the field is transcription rather than interpretation.

`tools/derive-expressions.pl` is the other direction, and it is the reason an
expression can be *proven* rather than proposed. **John's dynamic compiler
takes an expression on the command line**, so a candidate never has to be
believed: hand it to john against the entry's own vector and either it
recovers the entry's own plaintext or it does not. Candidates come from three
redundant generators -- the `name:` field, the entry `id` slug, and the mdxfind
type name -- and every one of them **bails on the first token it does not
know**. That rule is what keeps the tool honest: `MD5CAP`'s `CAP` is not in
the vocabulary, so no candidate is emitted, whereas silently dropping the
token would emit `md5($p)`, which john would happily "prove" because `cap()`
is a no-op on a lowercase digest. The function vocabulary is harvested from
john's own subformat listing, never hand-written.

Two guards, both non-negotiable. **Every vector the entry carries must fall,
not the first** -- an entry with three vectors and a candidate that cracks two
has found a coincidence, which is exactly how `dynamic_1011` looked like
`MD5PASSMD5`. And **if two different expressions each reproduce every vector,
nothing is written**: they agree on this entry's inputs, they need not agree
in general, and choosing between them is curation.

A proven expression is also an operational answer -- `john
--format=dynamic='haval128_3(md5($p))'` is a command someone can run today on
an entry that has no named john format at all. It belongs in
`john_dynamic_expr:`, **never in `tools.john.cpu`**: an ad-hoc expression is
not a john format identifier and putting it in the identifier column would
inflate john's coverage with something no `--list=formats` will ever show.

### `expression:` and `john_dynamic_expr:` are not always the same string

`expression:` is hx-style. hx spells a change of REPRESENTATION as a wrapper;
john spells it as a FLAVOR of the hash function, and rejects the wrapper form
outright:

    md5(upper(md5($p)))   hx        -- john: "Dyna expression syntax error"
    md5(MD5($p))          john      -- compiles, and cracks the same vector

    upper(F(x))       -> F_UPPERCASED(x)      lower(F(x))     -> F(x)
    hex(F_bin(x))     -> F(x)                 base64(F_bin(x))-> F_64(x)
    upper($p|$u)      -> uc($p|$u)            pad($p,100)     -> pad100($p)

`RosettaJohn::hx_to_john` does exactly those rewrites and REFUSES anything
else whole, on the same rule as `RosettaHx`: dropping a modifier is how a
wrong expression proves itself, since `cap()` on a lowercase digest and
`lower()` on a hex string are both no-ops on some inputs.
`derive-expressions.pl` hands john the rewritten string and records the hx
one, so an entry keeps hx notation in `expression:` and a runnable command in
`john_dynamic_expr:`. Where the two differ the proof note says so: they are
ONE claim written twice, not two agreeing pieces of evidence. `render.pl`
publishes `john_dynamic_expr` as its own CSV column for the same reason --
pasting the `expression` column after `--format=` is a syntax error on those
rows.

**Read john's LEXER, not its documentation, for what the language contains.**
`doc/DYNAMIC_EXPRESSIONS` names only `lc()` and `uc()`.
`src/dynamic_compiler.c` -- `comp_get_symbol`, the block after
`LARGE_HASH_EDIT_POINT` -- also has `pad16($p)`, `pad20($p)`, `pad100($p)`,
`utf16()` and `utf16be()`, and every hash has upper-case, `_raw`, `_64` and
`_64c` flavors. Measured 2026-09-02: believing the doc refused 19 radmin2
entries and 13 utf16 ones, on a day when 46 entries in this corpus already
carried a PROVEN `john_dynamic_expr:` containing `utf16()`. Not every token
the lexer accepts works: `pad16($p)` compiles and then dies with `unknown
flag: Flag=MGF_KEYS_INPUT_pad16` in this build, which is a defect in the
build rather than a fact about the notation, so it is still emitted and john
still gets to be the oracle.

### The expression carries its own tier

`expression:` is a gate -- `validate.pl` fails a build where two entries claim
the same one -- so it says how it was established, in the same vocabulary the
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

- `vector`   -- this exact string was compiled by john and recovered the
               entry's own plaintext from its own hash. Only
               `derive-expressions.pl` may write it.
- `upstream` -- john's `--list=subformats` states it for an identifier the
               entry already proved. `expressions.pl` writes this and nothing
               stronger: what was round-tripped is the *identifier*.
- `asserted` -- a human said so.
- `absent`   -- this algorithm has no expression in the dynamic language.

`validate.pl` enforces the pairing: an `expression:` with no
`expression_proof:` fails, `vector` with no vectors fails, and `absent`
alongside an expression fails.

### `denotation:` -- no expression, but still a way to refer to it

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
(`PBKDF2-HMAC-SHA256`, `7-Zip`). It is deliberately **not tiered** -- nothing
can round-trip it -- so it carries a `source:` instead and is never an
unattributed human claim. It is illegal alongside `expression:`: an entry with
both says the same thing twice at two strengths and a reader cannot tell which
to believe.

`--denote` writes this pair, and only where `absent` is a **checkable fact**
rather than a shrug: the name is already expression-shaped and at least one
function in it is not in the vocabulary harvested from john. That is a lookup,
not an opinion. Note what it does *not* say -- john has formats for HMAC-SHA1
and for bcrypt; it has no `hmac()` or `bcrypt()` token in the dynamic
*expression* language, and those are different sentences.

Entries whose name is not expression-shaped (`7ZIP`, `AIX-MD5`, `Tiger Tree
Hash`) are left alone rather than bulk-marked, because "no candidate could be
generated" is a fact about our generators, not about john.

`tools/denote-hx.pl` does the same job from a far better source: the hx
specification's own statement of what an mdxfind type computes. `--denote`
reads the entry's `name:`, which for most of these is just the mdxfind type
name and denotes nothing; Appendix A states the construction. So the
denotation is `source: "mdxfind"` in the schema's literal sense -- the tool's
own label for its own type, which is already in `tools.mdxfind.types`.

It qualifies an entry on two facts and nothing else: a function outside
**both** boundaries -- `RosettaHx`'s `%FUNC` and the vocabulary harvested from
john -- or a multi-emit type. Both boundaries are checked because `%FUNC`
admits `cut()` and `pad()` deliberately, so `%FUNC` alone would call them
grounds for `absent` and contradict `seed-hx.pl` on the same type. It refuses
a row that is prose rather than an expression (`Note [20]`, `(complex: ...)`),
because there upstream declined to state the construction and that is a shrug.

**`denotation:` forecloses an `expression:`,** because `validate.pl` forbids
both, so never denote something that might yet be provable. Concretely:
**john's dynamic language has constants and a second salt** --
`md5($c1.$p),c1=x` compiles and cracks, and `$s2` is real (`doc/DYNAMIC_EXPRESSIONS`
lines 53-73). None of the generators here know that yet, which is why
`denote-hx.pl` leaves the `stray-literal` and `unknown-operand` residue alone.

`--repair` withdraws an `expression:` that is not well-formed in this
repository's notation. A claim nothing can compile is withdrawn, never
adjusted: guessing what upstream meant is the thing the expression field
exists to prevent. The withdrawal note stays on the entry even after a
denotation settles it.

## Collisions: when two entries mean the same thing

The moment expressions existed, nine of them turned out to be claimed by more
than one entry. That is not noise -- it is the `id` being asked to carry four
independent facts at once: the **computation**, the **representation** (hex
case, base64, a `$1$` wrapper), the **deployment** (Joomla, vBulletin 3.8.5,
osCommerce -- which hashcat gives separate modes), and the **tool identifier**.
Only the last was ever modeled.

So an entry carries three fields for it. `category:` names the axis it sits on
-- `primitive`, `composite`, `iterated`, `encoding`, `application`, `protocol`,
`kdf` -- with `application:` and `application_version:` for a product row.
`relations:` is a typed, symmetric edge list:

    relations:
      - kind: "same-computation"
        entry: "md5-pass-salt"
        distinction: "application"
        note: "hashcat separates these: mode 11 assumes Joomla's fixed-length
               salt, mode 10 is the generic construction"

`kind` says what the relationship is -- `same-computation`, `encodes`,
`input-encoding`, `iterates`, `truncates`, `collides-on-subset`,
`duplicate-of`. `distinction` says why both rows nonetheless exist --
`application`, `encoding`, `input-encoding`, `iteration`, `truncation`,
`salt-convention`, `naming`, `none`. `none` is legal only with
`duplicate-of`, which is how a merge gets proposed in data rather than in a
comment. `naming` is its answer: a curator looked at a proposed duplicate and
decided both names keep a row, because the tools publish several identifiers
for one computation and each row is where a reader arrives from a different
name. mdxfind alone has `MD4UTF16`, `NTLM` and `NTLMH` for `md4(utf16($p))`.
A machine still writes `duplicate-of`; only a person writes `naming`.

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
- **Some mdxfind types are MULTI-EMIT and cannot have one `expression:`.**
  Found 2026-08-31 in the hx specification (rev 1.15) Appendix A, Note [24].
  Such a type computes SEVERAL candidate digests per input and matches if any
  one reproduces the stored hash. `MD5MD5USER` emits both `md5(md5($p).$u)` and
  `md5(md5($p).":".$u)`; the HEXSALT family emits three digests per candidate
  byte across all 256; the TRUNC family sweeps a truncation length and emits
  both a left and a right truncation at each; the DSALT types emit four
  colon-aware variants plus a 119-value byte search. A single `expression:` on
  such an entry is a false claim even when the string is one of the forms, so
  use `denotation:` and say in it that the type is multi-emit. This is also the
  explanation for entries whose vectors "disagree with each other": two vectors
  of one multi-emit type are both correct, and a tool matching one of them is
  not evidence about the other.
  **Note [24] is not the whole population.** It names 34 types; Appendix A
  ALSO spells `emit()` in the expression for 14 more, and the two sets are
  disjoint (measured 2026-08-31), so at least 48 types are multi-emit. Ask
  `RosettaHx::is_multi_emit()`, which reads both, and never re-derive the list
  from the note alone.
  **And Appendix A's row can be wrong about the very types the note covers.**
  e308 `SHA1MD5USER` reads `sha1(md5(user))` and e354/e355 likewise -- the
  password operand is missing, where e286 `MD5MD5USER` writes it correctly.
  Note [24] gives the real forms. Any transcription must refuse a row that
  never mentions the password; that is the same `$p` guard the expression
  generators use, and it is why upstream's own statement still gets checked.
- **If a source tracks it separately, it gets its own findable row.** Decided
  2026-08-31 by Royce. When hashcat, john or mdxfind publishes a distinct
  identifier, someone will arrive here by that identifier and must land on a
  row that describes what it actually computes. `MD5MD5USER` (e286) is
  `md5(md5($p).":".$u)` -- a literal colon before the userid field, hx.pdf note
  24 p.58 -- and its row had been carrying the expression, the john dynamics
  and a vector of the colonless `md5(md5($p).$s)` beside it, so the row was
  findable by name and wrong about the algorithm. Note what this does NOT
  imply: the fix needed no new `id`, because the row already existed under the
  right mdxfind type. Check whether the row is merely mis-described before
  reaching for a split, and remember that separately-tracked is not the same as
  separately-computed -- `MD5CAPMD5USER` differs only by a `cap()` that is a
  no-op on a digest starting with a digit, which is a `collides-on-subset`
  edge, not an equivalence.

### A merged-away id becomes a tombstone

Decided 2026-08-30, and it is what unblocks acting on a `duplicate-of` /
`distinction: none` proposal. The loser's file stays, emptied of every claim:

    id: "ripemd320"
    name: "ripemd320"
    status: "merged"
    merged_into: "rmd320"
    relations:
      - kind: "duplicate-of"
        entry: "rmd320"
        distinction: "none"
        note: "merged 2026-08-30; ..."
    notes: "Tombstone. ..."

`aliases:`, `legacy:`, `vectors:` and every tool identifier move to the
survivor -- that is the merge -- and the tombstone keeps nothing but the
redirect. `validate.pl` enforces that: `merged_into` and a mirrored
`duplicate-of` edge are both required, the destination must exist and must not
itself be a tombstone (repoint the first one instead of building a chain), and
any of `expression`, `tools`, `vectors`, `aliases`, `legacy`, `category` on a
tombstone is an error. A tombstone is excluded from every count and coverage
denominator: it is not an algorithm.

`render.pl` gives it a row in `dist/rosetta.csv` and `rosetta.json` -- the old
`id` still joins -- with every claim column empty, `status` `merged` and a
`merged_into` column naming the survivor, so a consumer is told where the row
went instead of having to parse the relations prose. The two human views list
it under the table rather than in it, because a row of dashes reads as a gap
and this is a redirect.

`tools/merge.pl` performs the merge, both sides at once. **`tools/dedupe.pl`
does not** -- it predates this decision and DELETES the loser, which breaks the
promise that an id is forever; treat it as retired. merge.pl refuses rather
than resolves two things, because both would launder an unproven claim into a
proven one: a loser whose tool block is at a WEAKER tier than the winner's,
since a block carries one tier for every identifier in it and unioning would
extend the winner's over identifiers nothing proved at that strength; and a
single-valued field the two entries fill differently, which means they are not
one computation. Note what validate.pl does NOT check: it requires every edge
to be mirrored and to point at a real entry, but not that an entry states a
given edge only once, so a merge that leaves the stale pre-merge `duplicate-of`
beside the new one passes.

The full design, the options weighed against it and what changed on contact
with the code are in `ACTION-PLAN.md` section 11.

## The published contract

Some things are promised to people outside this repository, in README's "What
you can depend on". They are cheap to break by accident and expensive to
un-break, so they are restated here where a tool gets written:

- **An `id` is forever.** Filename stem, URL fragment, CSV key. A merge makes
  the loser a tombstone (`status: merged` + `merged_into:`), never a deletion
  and never an `mv`.
- **CSV columns may be added, never renamed or removed** without saying so in
  the README. Consumers are told to read by header name, which is what makes
  adding one safe.
- **The four tiers are fixed vocabulary.** Adding a fifth, or redefining one,
  is a breaking change to every consumer's interpretation of every row.
- **`docs/` and `dist/` are generated.** Anything hand-edited there is lost on
  the next render, and `render.yml` will do that render without being asked.
- **Both the code and the data are MIT.** Anything vendored has to be
  compatible and has to be recorded in `vendor/*/PROVENANCE.md` with the
  upstream commit.

## Conventions

- ETL and tooling in **Perl** (see global CLAUDE.md). The one-shot sheet
  importer is Python only because `openpyxl` is the practical xlsx reader;
  flag any further Python additions.
- Data files are YAML, UTF-8, LF, 2-space indent, keys in schema order.
- Generated files carry a `# GENERATED by tools/<x> -- do not edit` header and
  the source tool version.
- Scripts: no args => usage + exit 2. `--verbose` to stderr, data to stdout.
  Counts and elapsed time to stderr on bulk runs.
- Scale is small -- ~1000 mdxfind types, ~600 hashcat modes, ~400 john formats.
  Plain hashes are fine; no need for anything cleverer.
