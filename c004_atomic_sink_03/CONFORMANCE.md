# Implementation conformance obligations

**No adapter in this repository is qualified for the atomic timed interface.** This document specifies the next implementation evidence, rather than automatically granting capability when metadata fields are filled. A pure simulator passing its own model is not that implementation.

| Obligation | Reviewable evidence required | Current status |
|---|---|---|
| Actual effect point | Identify the irreversible database/device effect and its linearization point, rather than API entry, reply time or a preparation callback | Not supplied for an implemented timed primitive |
| Deadline coupling | Show validation and that effect are one trusted operation, or prove the complete hard delay and clock-error bounds in candidate02 | Unqualified |
| Clock and faults | Reference domain, resolution/error, origin/boot changes, pause model, clock-fault treatment before irreversible effect | Only finite abstract clock here |
| Revocation order | Current-epoch change serialized in the same authoritative effect order; distinguish request receipt from committed R | Abstract model only |
| Identity and all effect paths | Verify signatures/caller and all request bindings; prevent direct writes, alternate owners, bypass APIs and forged cache access | Fixed predicates in model; no platform security qualification |
| One consumption, retained result | Atomic effect+consumption+result, immutable request binding, lost-response recovery without re-execution | Assumed atomic model transition; physical storage evidence needed |
| Crashes and restore | Demonstrate actual kill/power-loss behavior in scope; preserve authority/results/clock domain; specify clones and restoration boundaries | Model crashes only; no power-loss or restoration claim |
| Trace collection | Capture invocations/replies, committed revocations, fault receipts, retained state and trusted timing/causal bounds; preserve UNKNOWN | Model graph/probes only |
| Refinement | Map every implementation action/fault to permitted abstract behavior and validate hidden internal intervals before effect | Not supplied |
| Independence | External review/reproduction with its own trust assumptions and provenance | Same-author reproduction only |

## Required adapter-facing schedules

The ten named model paths are a portable acceptance brief: expiry between prepare/commit; committed revocation between prepare/commit; clock fault in that interval; crash of pending work; response lost after effect followed by crash, expiry, restart, revocation and exact retry; conflicting/forged history requests; valid next-epoch effect; equality at the deadline; cached history under clock fault; and restart refusing to heal a clock fault.

A real adapter would need to reproduce those **observable behaviors**, plus its internal adversarial pause points and actual retention/fault model. Replaying model labels as real receipts is inadmissible. A direct binding to this producer is not a physical adapter. A finite suite is necessary evidence for the stated cases, not sufficient proof that all real schedules refine the model.

## Candidate disposition

- Existing application sample, preparation authorizer, actual commit hook and nominal margin: not qualified for D by received studies01/02. Their bounded sampled-admission properties are not relabelled.
- A bounded real-time SQLite/storage path: possible conditional route, but no complete platform-bound evidence is available in this task.
- A sink/device/storage service with a documented and enforced timed atomic operation: interface target; no such connected primitive is identified or qualified here.
- Refusing every new effect avoids late effects but does not establish useful availability or implement a qualified primitive. A service requiring D must surface unavailable capability rather than falsely claim it.

The next implementation milestone is a **specific supplier/platform candidate with evidence for deadline coupling**, followed by adapter refinement and fault captures. Another ordinary callback or a larger configured margin is not that milestone. No deployment, external purchase or provider commitment follows from this document.
