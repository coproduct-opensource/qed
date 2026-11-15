import Lake
open Lake DSL

-- QED visit analytics: what the collector means (`QedAnalytics/Spec.lean`),
-- the Charon + Aeneas translation of its Rust core (`generated/`, never
-- edited by hand), and the proofs that the translation computes the spec
-- (`QedAnalytics/Refines.lean`). contracts/analytics/README.md.
--
-- Pins are those of Nucleus's `crates/ck-policy/lean-aeneas` package: the
-- Aeneas Lean library at the commit of release `nightly-2026.06.10` (whose
-- Charon and Aeneas binaries produce `generated/`), Mathlib at v4.30.0.
-- Aeneas's library requires Mathlib, so the generated code cannot be read
-- without it; the spec uses Mathlib for `ENNReal` sums.
package «qedAnalytics» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`maxHeartbeats, (1000000 : Nat)⟩
  ]

require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "5138c03bd39e870abe1ad3a572865cf8c15f43d6" / "backends" / "lean"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.30.0"

require «axiom-audit» from git
  "https://github.com/leanprover-community/axiom-audit" @ "v0.1.2"

@[default_target]
lean_lib «QedAnalytics» where
  roots := #[`QedAnalytics]
