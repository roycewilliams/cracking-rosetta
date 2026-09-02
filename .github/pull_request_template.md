<!-- Short PRs are easy to accept. One algorithm per PR is ideal. -->

## What this changes

<!-- Which entry or entries, and what you are asserting about them. -->

## How it was established

Every mapping carries a tier, and the tier is the whole point of this
repository. Tick what applies:

- [ ] **`vector`** -- I ran the tool, pinned to that exact identifier, and it
      recovered the plaintext from the entry's own test vector. Command and
      output pasted below.
- [ ] **`upstream`** -- a project that verifies by recomputation says so
      (mdxfind's type table, hashpipe's `john_map.h`). Named below.
- [ ] **`asserted`** -- I know this to be true but have not reproduced it.
      That is a fine thing to contribute; it just has to say so.
- [ ] Not a mapping change (docs, tooling, typo).

```
paste the command and its output here
```

## Checks

- [ ] `tools/validate.pl` passes
- [ ] `tools/fmt.pl --all --check` passes
- [ ] I did not hand-edit anything under `data/tools/` or `docs/` or `dist/`
      (all generated)

<!-- No need to regenerate docs/ or dist/ -- CI does that after merge. -->
