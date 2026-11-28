# The library exclusion set

`lean-4.30.0-init.exclude`: 57,425 keys, 32 bytes each, sorted. Each is
`qed_savings::walk::key` (SHA-256 of a tag, the dotted name and the Merkle
digests of type and value) of one declaration of the Lean 4.30.0 library.
No declaration in it earns an author's share (`Savings.excluded_never_earns`).

Made on 2026-11-28 with the exporter statements use (lean4export 3.1.0,
source `a3e35a5`, built with Lean 4.30.0 commit
`d024af099ca4bf2c86f649261ebf59565dc8c622`):

```text
lake env .lake/build/bin/lean4export Init > init.ndjson
qed-library-keys init.ndjson lean-4.30.0-init.exclude \
  propext Quot.sound Classical.choice Lean.trustCompiler Lean.ofReduceNat Lean.ofReduceBool sorryAx
```

| | |
|---|---|
| `init.ndjson` | 339,987,086 bytes, SHA-256 `75b2cb000d698aac2946ea76d3401d5939c9274ebd7849d1b46f25ee2fcd28d9`, 9.9 s, exporter stderr empty |
| keys | 57,425; a second run wrote the same bytes |
| set SHA-256 | `ef997b9fa3c0b7fc42478f8f151162b84a5b3849b06c2a4ab393c99aa56897dd` |
| `qed-library-keys` | 3.2 s, 1.41 GB peak resident (the checker's parser); 7.1 s, 1.38 GB (the `walk::export` reader, 2026-11-28), the same bytes |

The keys are made by `walk::export`, the reader the walk uses, which shares no
code with the proof guests; it was first made with the vendored checker's
parser, and the reader reproduces it byte for byte. The axioms on the command
line are no longer read.

The export is not committed (340 MB); the command above remakes it. The
axioms are the ones `Init` declares; the parse refuses an export that
declares one not listed. `Init` only: a statement exports from the
prelude, and `Std` or `Lean` declarations a seller re-exports are still
credited to their first carrier.
