# Contributing to cracking-rosetta

Most of what this project needs is **information**, not code: a mapping that's
missing, a mapping that's wrong, and above all test vectors. If you know that
hashcat mode 4110 is what John calls `dynamic_11`, and you have a hash that
proves it, that's a contribution.

You do **not** need hashcat, John or mdxfind installed to contribute. The
checks you run before opening a PR are pure text.

## What you'll need

- `git` and a text editor
- `perl` (any version this decade) and the YAML module:
  - Debian/Ubuntu: `sudo apt install libyaml-libyaml-perl`
  - Fedora/Rocky: `sudo dnf install perl-YAML-LibYAML`
  - FreeBSD: `pkg install p5-YAML-LibYAML`

## The three commands

Run these before you open a pull request. Together they take a couple of
seconds.

```sh
tools/fmt.pl --all              # put your edit in the house YAML style
tools/validate.pl --changed     # check just what you changed
tools/review-delta.pl           # show what your change actually claims
```

`validate.pl --changed` checks the whole repository but only reports errors in
*your* entries, so you never have to hunt for your own mistake in someone
else's. If it mentions errors "elsewhere in the corpus", those aren't yours
and won't block you.

`fmt.pl` is worth running even if your YAML looks fine. Every file here is
written in one canonical style, and matching it keeps your diff the size of
your change. It also catches the mistake nothing else will: if you misspell a
key, `fmt.pl` tells you, where otherwise the line would be silently dropped
the next time a tool touches the file.

## I want to...

### ...add a test vector

This is the most valuable thing you can contribute, and the easiest. A vector
is a hash and the plaintext that produces it. It's what lets anyone else
promote a mapping from "someone said so" to "we ran it".

```yaml
vectors:
  - hash: "45b1a3b4d0d4b1e4a5b3d9ee08e0e0c7:tj81ZLT"
    pass: "rosetta"
    source: "hashcat's example hashes"
```

Salted hashes go in as `hash:salt`. Say where you got it in `source:` — a
tool's example hash, a public test corpus, "generated it myself" are all fine.
Please don't contribute a hash from real data.

### ...add a mapping a tool is missing

Find the entry in `data/algorithms/`, add the block, and be honest about the
tier:

```yaml
tools:
  john:
    cpu: ["dynamic_11"]
    verified: "asserted"
    note: "from the hashcat wiki; not reproduced"
```

Use the exact identifier the tool prints — `Raw-MD5` on CPU but
`raw-MD5-opencl` on GPU, John is inconsistent about case. If you name an
identifier no installed tool has, `validate.pl` will tell you.

### ...fix a mapping that's wrong

Don't overwrite the old claim — add yours in `note:` and say so in the PR.
Disagreements here get settled by verification, not by whoever edited last.

### ...add an algorithm that isn't here

One file, named after its `id`, in `data/algorithms/`. The minimum:

```yaml
id: "example-thing"
name: "Example Thing"
status: "needs-review"
tools:
  hashcat:
    modes: [12345]
    verified: "asserted"
vectors:
  - hash: "<a hash>"
    pass: "<its plaintext>"
    source: "where you got it"
```

Run `tools/fmt.pl data/algorithms/example-thing.yaml` and it'll be tidied into
the house style. The full field list is in `schema/algorithm.schema.json`.

### ...say two entries are the same thing

Don't merge them yourself — propose it in the data:

```sh
tools/relate.pl --kind same-computation \
    --entry joomla --with md5-pass-salt \
    --distinction application \
    --note "hashcat 11 assumes Joomla's salt; 10 is generic" --apply
```

That writes **both** sides of the relation, which is required. `kind` is one
of `same-computation`, `encodes`, `input-encoding`, `iterates`, `truncates`,
`collides-on-subset`, `duplicate-of`. `distinction` says why both rows still
exist: `application`, `encoding`, `input-encoding`, `iteration`, `truncation`,
`salt-convention`, or `none`.

If you think there's genuinely no difference left, use
`--kind duplicate-of --distinction none`. That's the proposal; a maintainer
does the merge, because an `id` is a published key that other people's scripts
point at.

## The one rule: don't inflate tiers

`verified: vector` means **this repository cracked that vector with that tool,
pinned to that exact identifier**. It does not mean "I'm confident", and it
does not mean "the documentation says so".

If you haven't round-tripped it yourself, write `asserted` and say where the
claim came from. Someone will verify it later and promote it. An honest
`asserted` is worth far more than a hopeful `vector`, because the whole point
of this repository is that you can trust the `vector` rows without checking.

The automated checks on your PR deliberately never run a cracker, so this one
is on your honour — and it's the thing a maintainer will look at first.

## Files you may and may not edit

**Edit:** `data/algorithms/*.yaml` — one algorithm per file, filename stem
equal to the `id`.

**Don't edit:** `data/tools/*.yaml`, `docs/index.html`, `docs/ROSETTA.md`,
`dist/*`. All generated, all carrying a banner that says so. If a mode or
format is missing from an inventory, the fix is to re-run the extractor.

**Don't edit:** `vendor/`. Refresh it with `tools/fetch-upstream.sh` and send
that as its own PR, so the diff shows what upstream actually changed.

## Mistakes that are easy to make

- **One entry is one algorithm.** If your hash is computed differently from
  the entry you were going to put it in, it needs its own entry — even if the
  two share a name or a mode. `aliases:` is for other *names* of the same
  computation, not for related algorithms.
- **A tool cracking your vector doesn't mean it implements your algorithm.**
  `md5cap` is `cap(md5($p))`, which does nothing when the digest has no
  letters, so John's `dynamic_2` recovers its vector while computing something
  else. That's a `collides-on-subset` relation, not a mapping.
- **mdxfind's iteration count is part of the identity.** `MD5` at `-i 2` is
  `md5(md5($pass))`, which is John's `dynamic_2`, not `dynamic_0`. Record it
  as `tools.mdxfind.iterations`.
- **mdxfind's hashcat column lists *related* modes, not equivalents.** Type
  `MD5` names modes 0, 2600, 3500 and 5100 — four different algorithms. Don't
  copy such a list into one entry.
- **`id` never changes once it's published.** It's the filename, a link
  fragment on the rendered page, and the key in `dist/rosetta.csv`. If a name
  is wrong, add the better one to `aliases:`.

## Bonus: vanity vectors (optional, and very welcome)

A reference hash that is *visibly* a rosetta artefact is more fun than a random
one, and just as valid. Three rules make it work.

**Only salted algorithms.** For an unsalted hash the digest is a pure function
of the plaintext, so the only thing you could vary is the plaintext itself —
and keeping that pure matters far more than a pretty digest. Salted types give
you a free variable that nobody cares about, so that is where this belongs.

**The plaintext never moves.** It stays exactly `rosetta`. You search the
*salt*.

**Pick a marker that needs no decoding.** The point is to be recognised at a
glance, so heavy leetspeak defeats it — `ca7a109` for "catalog" is a puzzle,
not a marker. Hex is `0-9a-f`, and the only letters it can show are
`a b c d e f` plus `o`→`0`, `i/l`→`1`, `s`→`5`, `t`→`7`, `g`→`9`, `z`→`2`.
Prefer words needing **zero or one** substitution:

| marker | subs | reads as | GPU @20 GH/s |
|---|---:|---|---:|
| `dec0ded` | 1 | decoded | instant |
| `defaced` | 0 | defaced — the stone is a broken fragment | instant |
| `effaced` | 0 | effaced | instant |
| `abcdefaced` | 0 | the whole hex alphabet, plus "aced" | ~55 s |
| `defacedbeef` | 0 | nods to `deadbeef` | ~15 min |
| `dec0dedface` | 1 | decoded face | ~15 min |
| `decadefacade` | 0 | | ~4 h |

Four bits per character, so cost quadruples every character. Up to about 12 is
an afternoon; 14 is out of reach.

**A themed salt is a bonus, not a constraint — and you can usually have both.**
Salts of the form `rosetta<N>` are an unbounded family, so searching them is
just as deep a space as searching random salts: a 10-character marker needs
about 13 digits of `N`, a 12-character one about 15, giving a salt of ~22
characters that most formats accept happily. So the choice between "themed
salt" and "best digest" rarely arises. Where the format pins the salt short or
to a fixed alphabet — descrypt's two characters, a hex-only salt — **the
digest wins**; take a random salt and a good marker over a themed salt and a
poor one.

Worked examples, plaintext `rosetta` throughout, each verified with `md5sum`:

```
md5("rosetta" . "rosetta12426436") = decade0a494ed9b3cb23fa09af639b15
md5("rosetta" . "rosetta21442562") = facade391d27044cd1a3dad0852a5ec2
md5("rosetta" . "rosetta23158488") = dec1ded2121e9be4e236a816c438b0d1
md5("rosetta" . "rosetta13743570") = dec0de53931f54a32b25db2b530baea9
```

And the free tier, if you don't want to search at all: just use `rosetta` as
the salt. `mdxfind -z -s` will generate the vector for you, and both ends are
on theme at zero cost.

Housekeeping:

- A vanity vector is still a vector. It must verify like any other.
- Say how you made it in `source:` — `"vanity, salt search, md5 prefix"` is
  perfect.
- **Don't replace a good existing vector with a vanity one.** A vector from
  hashcat's example set is *evidence about hashcat*; one we generated is not.
  Vanity vectors fill gaps; they don't redecorate.
- Computing the hash with an implementation independent of hashcat, John and
  mdxfind makes it *better* evidence than one generated by a tool under test.
  Worth saying in `source:` too.

## What happens to your PR

CI runs the same checks you ran, plus a compile of every tool. It never runs a
cracker — verification has to happen on a machine with the tools and a GPU,
and a tier that a pull request could influence would be worthless.

A maintainer then runs `tools/review-delta.pl`, which lists what your change
claims and which claims need proving locally, and re-runs the ones that do. If
a `vector` claim doesn't reproduce, expect a question rather than a rejection
— a vector that won't crack can mean a wrong mapping, a wrong plaintext or a
missing salt, and those are worth telling apart.

## No GitHub account, or not comfortable with YAML?

Open an issue, or send the facts however is convenient. A mode number, a
format label and a test vector in a plain email is a perfectly good
contribution; someone will turn it into a file and credit you.

## Be nice

Keep PR descriptions lean. Using an LLM to help is fine — strip the padding
before you send it. Say what changed and why, and stop.
