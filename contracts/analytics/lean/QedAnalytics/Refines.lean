/-
The translated core computes the spec.

`QedAnalytics/Types.lean` and `QedAnalytics/Funs.lean` are Aeneas's
translation of `contracts/analytics/src/core.rs` (never edited by hand;
README.md says how to regenerate them). Each `*_refines` theorem below says
that a translated function returns `ok` (it never fails, so it never panics)
with a value whose abstraction is the spec function's value. The theorems at
the end restate the spec's guarantees over the translated functions.
-/
import QedAnalytics.Funs
import QedAnalytics.Spec

open Aeneas Aeneas.Std Aeneas.Std.WP Result

namespace QedAnalytics

open qed_analytics

theorem cells_eq : CELLS = 34 := rfl

theorem malformed_eq : core.MALFORMED = ok 32#usize := by
  obtain ⟨m, hm, hmv⟩ := spec_imp_exists
    (Usize.mul_spec (x := 2#usize) (y := 16#usize) (by scalar_tac))
  simp only [core.MALFORMED, core.PATHS, hm]
  congr 1
  apply UScalar.eq_of_val_eq
  simp [hmv]

theorem limited_eq : core.LIMITED = ok 33#usize := by
  obtain ⟨m, hm, hmv⟩ := spec_imp_exists
    (Usize.mul_spec (x := 2#usize) (y := 16#usize) (by scalar_tac))
  obtain ⟨z, hz, hzv⟩ := spec_imp_exists
    (Usize.add_spec (x := m) (y := 1#usize) (by scalar_tac))
  simp only [core.LIMITED, core.PATHS, hm, bind_tc_ok, hz]
  congr 1
  apply UScalar.eq_of_val_eq
  simp [hzv, hmv]

/-! ## Abstraction: translated values to spec values -/

def absCounts (a : Array U32 34#usize) : Counts := fun j => (a.val.getD j.val 0#u32).val

def absDay (s : core.Day) : Day := ⟨s.day.val, absCounts s.cells⟩

def absCell : core.Cell → Cell
  | .Suppressed => .suppressed
  | .Count v => .count v.val

def absRequest (r : core.Request) : Request :=
  ⟨r.path.val, r.first, r.day.val, r.second_of_day.val, r.peer.val.map (·.val),
    r.peer_port.val, r.head_bytes.val, r.body_bytes.val⟩

/-! ## Helpers -/

theorem length_34 (a : Array U32 34#usize) : a.val.length = 34 := by
  have := a.property; simpa using this

theorem fresh_eq (d : U32) : core.fresh d = ok ⟨d, Array.repeat 34#usize 0#u32⟩ := rfl

theorem absCounts_repeat : absCounts (Array.repeat 34#usize 0#u32) = fun _ => 0 := by
  funext j
  have hj : j.val < 34 := j.isLt
  simp only [absCounts, Array.repeat_val, List.getD_eq_getElem?_getD, List.getElem?_replicate]
  simp [hj]

theorem bump_refines (c : U32) : ∃ b, core.bump c = ok b ∧ b.val = bump c.val := by
  unfold core.bump bump
  by_cases h : c < core.num.U32.MAX
  · have hv : c.val < MAX := by
      have := (UScalar.lt_equiv _ _).mp h
      simpa [MAX, core.num.U32.MAX] using this
    simp only [h, if_true, hv]
    obtain ⟨z, hz, hzv⟩ := spec_imp_exists (U32.add_spec (x := c) (y := 1#u32) (by
      simp [MAX] at hv; scalar_tac))
    exact ⟨z, hz, by simpa using hzv⟩
  · have hv : ¬ c.val < MAX := by
      intro hc; apply h; apply (UScalar.lt_equiv _ _).mpr
      simpa [MAX, core.num.U32.MAX] using hc
    simp [h, hv]

theorem count_refines (s : core.Day) (i : Usize) (d : U32) (hi : i.val < CELLS) :
    ∃ t, core.count s i d = ok t ∧ absDay t = count (absDay s) ⟨i.val, hi⟩ d.val := by
  have hi34 : i.val < 34 := by simpa [cells_eq] using hi
  -- The shared tail: index, bump, update, on a day `t` already dated `d`.
  have tail : ∀ t : core.Day, t.day = d →
      ∃ u, (do
          let i1 ← Array.index_usize t.cells i
          let i2 ← core.bump i1
          let a ← Array.update t.cells i i2
          ok { t with cells := a } : Result core.Day) = ok u ∧
        absDay u = ⟨d.val, Function.update (absCounts t.cells) ⟨i.val, hi⟩
          (bump (absCounts t.cells ⟨i.val, hi⟩))⟩ := by
    intro t ht
    have hlen : i.val < t.cells.val.length := by rw [length_34]; exact hi34
    obtain ⟨x, hx, hxv⟩ := spec_imp_exists (Array.index_usize_spec t.cells i hlen)
    obtain ⟨b, hb, hbv⟩ := bump_refines x
    obtain ⟨a, ha, hav⟩ := spec_imp_exists (Array.update_spec t.cells i b hlen)
    refine ⟨{ t with cells := a }, by simp [hx, hb, ha], ?_⟩
    subst hav
    simp only [absDay, ht]
    congr 1
    funext j
    have hcell : absCounts t.cells ⟨i.val, hi⟩ = x.val := by
      simp only [absCounts, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hlen,
        Option.getD_some, hxv]
    rw [hcell, ← hbv]
    by_cases hj : j = ⟨i.val, hi⟩
    · subst hj
      have hlen' : i.val < ((t.cells.set i b).val).length := by
        simpa [Array.set] using hlen
      simp only [absCounts, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hlen',
        Option.getD_some, Function.update_self]
      simp [Array.set]
    · have hjv : j.val ≠ i.val := fun h => hj (Fin.ext h)
      simp [absCounts, Array.set, List.getD_eq_getElem?_getD, Function.update, hj,
        List.getElem?_set, Ne.symm hjv]
  unfold core.count count
  by_cases hlt : d < s.day
  · have hv : d.val < s.day.val := (UScalar.lt_equiv _ _).mp hlt
    exact ⟨s, by simp [hlt], by simp [absDay, hv]⟩
  · have hv : ¬ d.val < s.day.val := fun h => hlt ((UScalar.lt_equiv _ _).mpr h)
    by_cases hgt : s.day < d
    · have hgv : s.day.val < d.val := (UScalar.lt_equiv _ _).mp hgt
      obtain ⟨u, hu, hau⟩ := tail ⟨d, Array.repeat 34#usize 0#u32⟩ rfl
      refine ⟨u, by simpa [hlt, hgt, fresh_eq] using hu, ?_⟩
      rw [hau]
      simp [absDay, hv, hgv, fresh, absCounts_repeat]
    · have hgv : ¬ s.day.val < d.val := fun h => hgt ((UScalar.lt_equiv _ _).mpr h)
      have hsd : s.day = d := by
        apply UScalar.eq_of_val_eq; omega
      obtain ⟨u, hu, hau⟩ := tail s hsd
      refine ⟨u, by simpa [hlt, hgt] using hu, ?_⟩
      rw [hau]
      simp [absDay, hv, hgv]

theorem cell_refines (path : Usize) (first : Bool) :
    ∃ i, core.cell path first = ok i ∧ i.val = cell path.val first := by
  unfold core.cell cell
  by_cases hp : path < core.PATHS
  · have hpv : path.val < PATHS := by
      have := (UScalar.lt_equiv _ _).mp hp
      simpa [PATHS, core.PATHS] using this
    simp only [hp, if_true, hpv]
    have hb : 2 * path.val + 1 ≤ Usize.max := by
      have : PATHS = 16 := rfl
      scalar_tac
    cases first
    · obtain ⟨m, hm, hmv⟩ := spec_imp_exists (Usize.mul_spec (x := 2#usize) (y := path) (by
        scalar_tac))
      exact ⟨m, by simpa using hm, by simpa using hmv⟩
    · obtain ⟨m, hm, hmv⟩ := spec_imp_exists (Usize.mul_spec (x := 2#usize) (y := path) (by
        scalar_tac))
      obtain ⟨z, hz, hzv⟩ := spec_imp_exists (Usize.add_spec (x := m) (y := 1#usize) (by
        scalar_tac))
      exact ⟨z, by simp [hm, hz], by simp [hzv, hmv]⟩
  · have hpv : ¬ path.val < PATHS := by
      intro h; apply hp; apply (UScalar.lt_equiv _ _).mpr
      simpa [PATHS, core.PATHS] using h
    simp only [hp, if_false, hpv]
    exact ⟨32#usize, malformed_eq, rfl⟩

theorem step_refines (s : core.Day) (path : Usize) (first : Bool) (d : U32) :
    ∃ t, core.step s path first d = ok t ∧
      absDay t = step (absDay s) path.val first d.val := by
  obtain ⟨i, hi, hiv⟩ := cell_refines path first
  have hlt : i.val < CELLS := hiv ▸ cell_lt path.val first
  obtain ⟨t, ht, hat⟩ := count_refines s i d hlt
  refine ⟨t, by simp [core.step, hi, ht], ?_⟩
  rw [hat]
  unfold step cellIdx
  congr 2

theorem limit_refines (s : core.Day) (d : U32) :
    ∃ t, core.limit s d = ok t ∧ absDay t = limit (absDay s) d.val := by
  have h33 : (33#usize).val < CELLS := by decide
  obtain ⟨t, ht, hat⟩ := count_refines s 33#usize d h33
  refine ⟨t, ?_, by rw [hat]; rfl⟩
  simp [core.limit, limited_eq, ht]

theorem handle_refines (s : core.Day) (r : core.Request) :
    ∃ t, core.handle s r = ok t ∧ absDay t = handle (absDay s) (absRequest r) := by
  obtain ⟨t, ht, hat⟩ := step_refines s r.path r.first r.day
  exact ⟨t, by simp [core.handle, core.project, ht], by simp [hat, handle, project, absRequest]⟩

theorem publish_cell_refines (c g1 g2 : U32) :
    ∃ x, core.publish_cell c g1 g2 = ok x ∧
      absCell x = publish c.val ((g1.val : ℤ) - g2.val) := by
  unfold core.publish_cell publish
  by_cases hk : c < core.K
  · have hkv : c.val < K := by
      have := (UScalar.lt_equiv _ _).mp hk
      simpa [K, core.K] using this
    exact ⟨.Suppressed, by simp [hk], by simp [absCell, hkv]⟩
  · have hkv : ¬ c.val < K := by
      intro h; apply hk; apply (UScalar.lt_equiv _ _).mpr
      simpa [K, core.K] using h
    have hc := c.hBounds
    have h1 := g1.hBounds
    have h2 := g2.hBounds
    obtain ⟨a, ha, hav⟩ := spec_imp_exists
      (UScalar.hcast_inBounds_spec .I64 c (by simp [IScalar.max]; scalar_tac))
    obtain ⟨b, hb, hbv⟩ := spec_imp_exists
      (UScalar.hcast_inBounds_spec .I64 g1 (by simp [IScalar.max]; scalar_tac))
    obtain ⟨e, he, hev⟩ := spec_imp_exists
      (UScalar.hcast_inBounds_spec .I64 g2 (by simp [IScalar.max]; scalar_tac))
    obtain ⟨f, hf, hfv⟩ := spec_imp_exists (IScalar.add_spec (x := a) (y := b)
      (by simp [IScalar.min]; scalar_tac) (by simp [IScalar.max]; scalar_tac))
    obtain ⟨g, hg, hgv⟩ := spec_imp_exists (IScalar.sub_spec (x := f) (y := e)
      (by simp [IScalar.min]; scalar_tac) (by simp [IScalar.max]; scalar_tac))
    refine ⟨.Count g, by simp [hk, ha, hb, he, hf, hg], ?_⟩
    simp only [absCell, hkv, if_false, hgv, hfv, hav, hbv, hev]
    ring_nf

/-! ## The guarantees, over the translated code -/

/-- **(a) Noninterference, over the translated `handle`.** Two requests that
agree on `(path, first, day)` leave the same state, whatever their peer
address and port, time within the day, or head and body sizes. -/
theorem core_handle_noninterference (s : core.Day) (r₁ r₂ : core.Request)
    (hp : r₁.path = r₂.path) (hf : r₁.first = r₂.first) (hd : r₁.day = r₂.day) :
    core.handle s r₁ = core.handle s r₂ := by
  simp [core.handle, core.project, hp, hf, hd]

/-- The translated `handle` never fails, and its result is the spec's. -/
theorem core_handle_total (s : core.Day) (r : core.Request) :
    ∃ t, core.handle s r = ok t ∧ absDay t = handle (absDay s) (absRequest r) :=
  handle_refines s r

/-- **(b) The threshold, over the translated publisher.** A cell whose true
count is under 10 is published as `Suppressed`, whatever the noise. -/
theorem core_publish_suppresses (c g1 g2 : U32) (h : c.val < 10) :
    core.publish_cell c g1 g2 = ok .Suppressed := by
  have hk : c < core.K := (UScalar.lt_equiv _ _).mpr (by simpa [core.K] using h)
  simp [core.publish_cell, hk]

/-- **(c) The published value is the spec's**, true count plus `g1 - g2`, so
the publisher's output law is `cellDensity` whenever `g1 - g2` has law `lap`
(`difference_nonneg`, `difference_neg`), and `day_dp` applies to it. -/
theorem core_publish_is_spec (c g1 g2 : U32) :
    ∃ x, core.publish_cell c g1 g2 = ok x ∧
      absCell x = publish c.val ((g1.val : ℤ) - g2.val) :=
  publish_cell_refines c g1 g2

end QedAnalytics
