# EBUT file-audit challenge policy

This patch enforces the intended sampling policy for private file proofs.

## Challenge timing

The upload proof now carries `file_challenge_nonce`, which must be a server-provided unpredictable challenge generated after the file commitment/root is fixed. The verifier uses this nonce to derive challenged block indices. It no longer uses the user-created file commitment nonce as the audit challenge.

This matters because a user-chosen challenge nonce lets a malicious client search for indices that avoid bad blocks.

## Small files

Files with `file_size <= 100 KiB` are fully challenged. For tests, the policy test uses a 50 KiB file size so the suite validates the small-file path without requiring 100 KiB test data.

## Large files

Large files are spot-checked with a fixed cap:

- `MAX_AUDIT_CHALLENGES = 100`
- default confidence = `0.90`
- default assumed cheating fraction = `10%` bad blocks

The sample count is computed using the exact hypergeometric miss probability for sampling without replacement. The verifier enforces exactly the expected challenge count; a client cannot submit fewer challenged blocks.

Important: no finite capped sample can prove that a huge file has zero bad blocks. It only gives a catch probability under an assumption like “at least 10% of blocks are bad.” If the attacker corrupts one block in a million, a 100-block sample cannot catch it with 90% probability.
