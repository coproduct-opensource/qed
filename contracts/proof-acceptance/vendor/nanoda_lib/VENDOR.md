# Vendored nanoda_lib

Upstream: https://github.com/ammkrn/nanoda_lib, revision
`0da9f98feadd3a0a2ef4b3dbcf52a298a6fef929`, version 0.4.32, Apache-2.0
(`LICENSE` in this directory). Source archive from codeload, SHA-256
`5220eab09bbad821ffcbc2fb4fdb435f5601eea900707d0109ec072f88c3ba29`.

This revision contains the nested-inductive constructor field-count check
(upstream PR 63). `docs/rfcs/proof-commerce-kernel-validation-2026-11-11.md`
records that the check refuses the known malformed export and that removing it
lets that export pass.

## Changes from upstream

1. `src/acceptance.rs` is added and `src/lib.rs` declares it. It exposes
   in-memory, single-thread checking and a per-declaration summary. It calls
   the same parser and `check_declar` as the upstream binary.
2. `src/parser.rs`: three `std::process::exit(2)` calls on a back-reference
   mismatch are replaced by `panic!` with the same message. Upstream ends the
   whole process there; as a library on untrusted input that would end a
   relayer. Every other refusal in the parser and kernel is already a panic.

Nothing else differs. `diff -r` against the extracted archive shows only these
files.

## Added for checked base libraries (2026-11-12)

3. `src/parser.rs`: `parse_export_file` now calls a new
   `parse_export_file_marked`, which is the same loop with one addition: for
   each byte offset given as a mark it records how many declarations existed
   when exactly that many bytes had been read. A mark that is not at a line
   end, or lies past the input, is an error. With no marks the function reads
   and interprets every line as before; the lines are handed to the same
   `go1`.
4. `src/acceptance.rs`: `inspect_after(export, permitted_axioms, marks)`
   parses once with marks and runs the upstream `check_declar`, unchanged, on
   every declaration made after the first mark. It does not check the
   declarations made before it. That is the whole point, and it is sound only
   when the caller holds evidence that those bytes checked as an export of
   their own under the same axioms with this checker
   (`docs/rfcs/proof-commerce-checked-bases-2026-11-12.md`). The count of
   declarations before the mark comes from the parser, not from the caller.
   Before checking, it refuses any constructor or recursor after the mark
   that names an inductive type declared before it. An inductive's check
   compares the recursors the file attaches to it with the ones it derives;
   for an inductive before the mark that check is not run here, so nothing
   after the mark may attach to it. This revision's parser already refuses
   such a block (`check_inductive_block` requires a block's constructors and
   recursors to belong to the block's own types), so the added refusal has
   not fired in any test; it is kept in case the parser's rule changes.
   The summary-building loop of `inspect` moved into a function both share.

No kernel check is weakened for any declaration that is checked: the same
`check_declar` runs on it against the same whole-file tables.

## Added for statement format v2, stage 1 (2026-11-13)

`docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md`.

5. `src/parser.rs`: `ExportJsonObject` no longer derives `Deserialize` with
   two `#[serde(flatten)]` fields. A hand-written implementation reads the
   line object's keys once: `in`, `il`, `ie` give the back-reference; the one
   other key names the variant of the still-derived `ExportJsonVal`, and its
   value is deserialised in place (`Tagged`, `TaggedValue`). serde's flatten
   buffered every line into an owned `Content` tree and read it twice. Lines
   with an unknown key, two value keys, two back-reference keys or no value
   key are refused with an error. Upstream ignored unknown keys; a line that
   carried one and lacked its back-reference then failed later by panic, so
   such a line was refused before too, with a different kind.
6. `src/parser.rs`: `parse_export_segments_marked` reads the concatenation of
   input slices in place: it splits each at `\n`, checks each line is UTF-8
   (as `read_line` did) and calls the same `go1`. Every segment but the last
   must be empty or end with a newline. The post-loop work moved into
   `finish`, shared with `parse_export_file_marked`, which keeps reading a
   `BufRead` for the upstream binary.
7. `src/acceptance.rs`: `inspect_segments` and `inspect_after_segments`, the
   in-place forms of `inspect` and `inspect_after`, which now call them.

No kernel check changes. Every declaration reaches `go1` and `check_declar`
with the same values: a differential run against the previous code on 334
fixtures, mutations and Nucleus exports gave the same accept/refuse verdict,
declaration count and proof name in every case, and the same refusal kind in
all but three (an artifact byte flipped `ie` into `id`: previously a panic,
now an error).

## Added for statement format v2, optimization pass (2026-11-13)

Same record, section "Optimization pass".

8. `src/parser/v2.rs`: the LEB128 reader returns a one-byte integer at once
   and accumulates longer ones in 64 bits instead of 128 (at most five
   bytes, 35 bits, for a 32-bit field). The rules are unchanged: shortest
   form, no wider than the field, no sixth byte, every byte bounds-checked.
   Each of the shortest-form and width checks was deleted once and
   `only_the_one_encoding_of_each_value_decodes` failed.
9. `src/parser.rs`: in the export v2 branch of
   `parse_export_segments_marked`, the expression and name tables are given
   a capacity of one entry per 13 and per 100 input bytes before parsing.
   Capacity only; nothing read or interned changes.
10. `src/parser.rs`: `ExportJsonVal::Metadata` holds its `FileMeta` in a
    `Box`, so a line's value is not as large as five strings. The JSON field
    names and values are unchanged (serde reads a `Box<T>` as a `T`).
11. `src/acceptance.rs`: `inspect_all_marked_segments`, for the base-less
    acceptance rule in one parse: parse once with marks, refuse any
    constructor or recursor after the first mark that names an inductive
    declared before it (the refusal `inspect_after_segments` already applies,
    moved into `refuse_attached_after`, which both call), then check every
    declaration with `check_all_declars_serial`. As for change 4, the parser
    already refuses such a block, so the refusal has not fired in a test.

No kernel check is weakened: every declaration is still checked by the same
`check_declar` against the same whole-file tables, and the base path is
unchanged. A differential run against the code before this pass on 1,139
cases (fixtures, the Nucleus exports, their mutations, NDJSON and v2) gave
the same accept/refuse verdict, declaration count and proof name in every
case; 98 refusal kinds changed, all from `StatementInvalid` (now
`ExportInvalid` or `KernelRefused`), as the one-parse rule expects.

## Kernel-reserved names, exported (2026-11-19)

`docs/rfcs/proof-acceptance-reserved-names-2026-11-19.md`.

12. `src/util.rs`: `NameCache`, `LeanDag::mk_name_cache` and a new
    `NAME_CACHE_NAMES` are generated by the macro `special_names!` (end of
    the file) from one invocation that lists upstream's fields in upstream's
    struct order and upstream's `field => "Dotted.Name"` lookups in
    upstream's lookup order; the compiler refuses the invocation if the two
    lists name different fields. `src/quot.rs`: `check_eq` and `check_quot`
    look `Eq` and `Eq.refl` up through the constants `EQ` and `EQ_REFL`
    (end of the file) instead of literals. `src/acceptance.rs` (end of the
    file): `is_kernel_reserved(name)` and `kernel_reserved_names()`, the union
    of the two lists, for the acceptance rule's refusal of seller
    declarations of those names.

No kernel check changes: the same names are looked up and compared in the
same places. `cargo clippy -p nanoda_lib --lib` reports the same findings as
before the change.

**It changes the base program's image.** The base guest links this crate,
so its image ID moves with any change here, even one that checks nothing
differently. *I first assumed that keeping every panic location in place
(the invocation on exactly the replaced lines, every addition at the end of
its file) would keep the base image; it did not.* The literals the name
cache looks up moved within the guest's read-only data
(`strings` of the two ELFs), so the image differs anyway
(`docs/rfcs/proof-acceptance-reserved-names-2026-11-19.md`, Programs).

## Savings attribution walk (2026-11-28)

`docs/rfcs/qed-proof-carrying-savings-2026-11-28.md`.

13. `src/acceptance.rs` (end of the file): `used_constants`, `Used` and
    `Walked`. One parse with marks and no kernel check, then a walk from a
    named declaration through the type and value of every constant reached,
    leaving out and not walking through `is_kernel_reserved` names, and a
    Merkle digest of each reached declaration's type and value under a
    caller-given hash (binder names and styles left out; constants by dotted
    name). For attributing reuse in artifacts that were already accepted;
    it decides nothing about acceptance.

No kernel check changes; nothing existing is edited, only appended. *Not
verified: whether the base guest's image ID moves.* The guest does not call
the new function, and item 12 showed an image can move without a check
changing; the `verify-programs` workflow rebuilds the guests and compares
image IDs, and is the check that settles it. `cargo clippy -p nanoda_lib
--lib` reports no finding in `src/acceptance.rs`.

Measured on the fixtures (`contracts/proof-acceptance/core/tests/used_constants.rs`):
the Nucleus artifact's seller side is four declarations, `rfl`,
`Nat.add_succ`, `Nucleus.helper` and `Nucleus.proof`: the artifact
re-exports two Lean library declarations its statement did not carry. The
285-byte v2 artifact settled for the bounty gives the same four, with the
same digests as the NDJSON fixture.

14. `src/acceptance.rs` (end of the file): `declaration_digests`, every
    declaration of an export with the digests of item 13, for building the
    library exclusion set (`contracts/savings/library/README.md`). Parse
    only; no kernel check. Appended; the same image-ID caveat as item 13.
