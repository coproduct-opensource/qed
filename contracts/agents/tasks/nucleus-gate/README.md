# Nucleus gate tasks

Three buyer-authored statements about the Aeneas-extracted gate functions of
Nucleus (`nucleus_ifc_kernel::exposure::should_gate`, `classify_operation`,
`nucleus_ifc_kernel::ifc_ops::is_exfil_operation`), and the task file each was
posted with. What they are, why these and not the 25 open rows of Nucleus's
`proof-obligations.toml`, the export commands and the posts are in
`docs/rfcs/proof-commerce-nucleus-open-obligations-2026-11-13.md`.

The statement exports are not here. A task file's `statement` path expects
`statement.ndjson` beside it, with these hashes:

    d8d7a2e663147ad39531d65a8d18cc7681e92e8871da2f0c935c5f9d3351e888  gate-soundness/statement.ndjson
    2076c16b31ceeb12f8d1b8dd29318b614ff9d33c9c08fb017c59f0855bfbcd59  gate-completeness/statement.ndjson
    72de15a79d753b017423704c4deafd378fcdc7c1c99745a14e8eb933d9b89828  exfil-classification/statement.ndjson

No proof of any of these claims is in this repository.
