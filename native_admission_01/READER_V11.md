# Versioned correction: receiver1.1

The original reader tests one mutation by setting the second client result's `new_allocation` to `True`. Two client processes are submitted before replies are collected, and the owner serializes requests. The second reply can legitimately be the one that created C. In that ordering, setting `True` is a no-op, leaving the original signed message intact, so the original mutation harness raises `ADMISSION_EVIDENCE_MUTANT_ACCEPTED`.

This was observed on the second public campaign CI42903610004 at source `ca110c6e45183cedc9da6858c6571f2dac8ec421`. It is a defect in the negative-test transformation, not evidence that two C were admitted or that an actually altered signed result was accepted. The original receiver and all failed captures remain preserved; no successful independent review is inferred.

Receiver1.1 inverts that boolean instead. Whichever client created C, the altered result must differ from its signed original and be rejected. Positive admission checks, counts, signatures, SQL preimage projection, policy, native engines and permissions are unchanged.

The original `sources/` directory and original source-manifest.json remain intact. `receive_v11.py` is the original admission reader with this single replacement, SHA256 `e9627d5b8989fe67b9e747f43de4dabbc448ef79b26f6eb62c2fadf3796908a4`. The launcher checks that exact byte transformation, stages the new reader as admission/receive.py, and creates an effective source manifest declaring the new hash, origin manifest and reader version. The native collector and all readers receive that effective manifest; no source mismatch is hidden.

A new native campaign is required for receiver1.1 reception. Direct diagnostic re-reading of earlier captures, if performed, must not be described as a new native run or retrospective success of a failed CI.
