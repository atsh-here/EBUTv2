# Accountable packed proof speed fix

The legacy `file_binding` accountable packed proof was spending most of its
runtime deriving Fiat-Shamir coefficients.

Old behavior:

```text
for every challenged block b:
  for every point j:
    hash the entire challenged transcript again
```

For a fully audited 50 KiB file this means thousands of coefficient hashes,
each replaying the whole challenged transcript.  The final legacy test could
therefore appear to hang for over 60 seconds.

New behavior:

```text
T = H(full challenged transcript)
alpha_{b,j} = H(T, b, j)
```

This keeps every coefficient bound to the complete public statement but removes
the quadratic hashing cost.  Prover and verifier use the same transcript digest,
so proof soundness semantics are unchanged for newly generated proofs.
