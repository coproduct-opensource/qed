# A base for Nucleus's extracted code

`roots.txt` lists the 1,613 root declarations of the base registered on
Arbitrum Sepolia on 2026-11-13. The base's bytes are not in the repository
(5,405,810 B). They are what this prints, with Lean 4.30.0, `lean4export`
3.1.0 at revision `a3e35a5`, and Nucleus's Aeneas and Mathlib build on the
library path:

    lean4export <any module that imports Aeneas> -- <the roots, in file order>

SHA-256 of the output, which is the base id:
`f21f1d5761ba89cd085a259cbf91f08ca37add451ce31b4a7feb8515b9d17e74`.

A statement that is to use the base is exported with these roots first and
its own roots after them. See
`docs/rfcs/proof-commerce-nucleus-base-2026-11-13.md`.
