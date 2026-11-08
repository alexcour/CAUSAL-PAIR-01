/-! CAUSAL-FIBER-01: toy model; not a production FCI proof. -/
universe u v w

def FiberConstant {H : Type u} {O : Type v} {V : Type w}
    (p : H → O) (v : H → V) : Prop :=
  ∀ a b : H, p a = p b → v a = v b

theorem factor_implies_fiber_constant
    {H : Type u} {O : Type v} {V : Type w}
    (p : H → O) (v : H → V)
    (r : O → V) (hr : ∀ h, v h = r (p h)) :
    FiberConstant p v := by
  intro a b hab
  rw [hr a, hr b, hab]

theorem collision_no_factor
    {H : Type u} {O : Type v} {V : Type w}
    (p : H → O) (v : H → V)
    (a b : H) (same : p a = p b) (different : v a ≠ v b) :
    ¬ ∃ r : O → V, ∀ h, v h = r (p h) := by
  rintro ⟨r, hr⟩
  exact different (factor_implies_fiber_constant p v r hr a b same)

def ImageReconstructible {H : Type u} {O : Type v} {V : Type w}
    (p : H → O) (v : H → V) : Prop :=
  ∃ r : (o : O) → (∃ h : H, p h = o) → V,
    ∀ h, v h = r (p h) ⟨h, rfl⟩

theorem image_reconstructible_iff_fiber_constant
    {H : Type u} {O : Type v} {V : Type w}
    (p : H → O) (v : H → V) :
    ImageReconstructible p v ↔ FiberConstant p v := by
  constructor
  · rintro ⟨r, hr⟩ a b hab
    calc
      v a = r (p a) ⟨a, rfl⟩ := hr a
      _ = r (p b) ⟨b, rfl⟩ := by
        have hx : (⟨p a, ⟨a, rfl⟩⟩ : {o : O // ∃ h : H, p h = o}) =
            ⟨p b, ⟨b, rfl⟩⟩ := Subtype.ext hab
        exact congrArg
          (fun x : {o : O // ∃ h : H, p h = o} => r x.val x.property)
          hx
      _ = v b := (hr b).symm
  · intro hc
    classical
    refine ⟨(fun o ho => v (Classical.choose ho)), ?_⟩
    intro h
    let ho : ∃ h' : H, p h' = p h := ⟨h, rfl⟩
    exact hc h (Classical.choose ho) (Classical.choose_spec ho).symm

inductive History where
  | timely | late | stale | missing
  deriving DecidableEq, Repr

inductive Observation where
  | receipt | noReceipt
  deriving DecidableEq, Repr

def observe : History → Observation
  | .timely | .late | .stale => .receipt
  | .missing => .noReceipt

def authorized : History → Bool
  | .timely => true
  | .late | .stale | .missing => false

theorem receipt_collision : observe .timely = observe .late := rfl
theorem verdict_collision : authorized .timely ≠ authorized .late := by decide

theorem no_reconstructor :
    ¬ ∃ r : Observation → Bool, ∀ h, authorized h = r (observe h) := by
  exact collision_no_factor observe authorized .timely .late
    receipt_collision verdict_collision

def enrichedObserve (h : History) : Observation × Bool :=
  (observe h, authorized h)

def enrichedReconstructor : Observation × Bool → Bool := Prod.snd

theorem enriched_exact (h : History) :
    authorized h = enrichedReconstructor (enrichedObserve h) := rfl

theorem extra_must_separate
    {E : Type u} (extra : History → E)
    (r : Observation × E → Bool)
    (hr : ∀ h, authorized h = r (observe h, extra h)) :
    extra .timely ≠ extra .late := by
  intro he
  apply verdict_collision
  calc
    authorized .timely = r (observe .timely, extra .timely) := hr .timely
    _ = r (observe .late, extra .late) := by rw [receipt_collision, he]
    _ = authorized .late := (hr .late).symm

theorem missing_refused : authorized .missing = false := rfl
theorem stale_refused : authorized .stale = false := rfl
theorem late_refused : authorized .late = false := rfl

/- Conservative authorization is weaker than exact verdict reconstruction.
   The observation map and the permitted-history predicate must be justified
   independently when connecting this theorem to a verifier. -/
def UniformlyAllowed {H : Type u} {O : Type v}
    (p : H → O) (allowed : H → Prop) (o : O) : Prop :=
  ∀ h, p h = o → allowed h

theorem conservative_sound
    {H : Type u} {O : Type v} (p : H → O) (allowed : H → Prop)
    (h : H) (permit : UniformlyAllowed p allowed (p h)) : allowed h :=
  permit h rfl

theorem sound_policy_iff_uniform
    {H : Type u} {O : Type v} (p : H → O) (allowed : H → Prop)
    (permit : O → Prop) :
    (∀ h, permit (p h) → allowed h) ↔
      (∀ o, permit o → UniformlyAllowed p allowed o) := by
  constructor
  · intro sound o hp h he
    apply sound h
    rw [he]
    exact hp
  · intro uniform h hp
    exact uniform (p h) hp h rfl

/- CAUSAL-PAIR-01 bridge: one quiescent operation, initial effects 0 or 1,
   restored empty receipt ledger, non-idempotent receiver. This finite model
   is linked to measured SQLite traces by bridge.py, not by a refinement proof. -/
namespace Recovery

inductive World where
  | empty | committed
  deriving DecidableEq, Repr

inductive Action where
  | execute | returnPrior | block
  deriving DecidableEq, Repr

def observation (_ : World) : Unit := ()

def required : World → Action
  | .empty => .execute
  | .committed => .returnPrior

theorem no_exact_recovery :
    ¬ ∃ r : Unit → Action, ∀ h, required h = r (observation h) := by
  exact collision_no_factor observation required .empty .committed rfl (by decide)

def effects : World → Action → Nat
  | .empty, .execute => 1
  | .empty, _ => 0
  | .committed, .execute => 2
  | .committed, _ => 1

theorem no_safe_and_live_shared_action :
    ¬ ∃ a : Action, effects .committed a ≤ 1 ∧ effects .empty a = 1 := by
  rintro ⟨a, ha⟩
  cases a <;> simp [effects] at ha

theorem block_safe (w : World) : effects w .block ≤ 1 := by
  cases w <;> decide

theorem block_not_live : effects .empty .block = 0 := rfl

end Recovery
