# Hidden-gap Emax revocation fix

The redemption verifier must not learn the containing revocation gap `(E_a,E_b)` because that leaks where the user's hidden `Emax` lies in the blacklist order.

This patch removes the public interval from `ClientRevocationProof` and relies on the real signed-gap ZK statement:

```text
exists Emax, E_a, E_b, blinders, signed gap sigma:
    sigma verifies on (revocation_context, E_a, E_b)
    C_B(Emax) and C_R(Emax) contain the same Emax
    C_B(E_a) and C_R(E_a) contain the same E_a
    C_B(E_b) and C_R(E_b) contain the same E_b
    E_a < Emax < E_b
```

The verifier sees commitments and blinded signatures, not `(E_a,E_b)`.

Anti-stale and anti-broad-gap security is achieved by binding each server gap signature to a public revocation context scalar:

```text
gap_ctx = H(app_id, policy_id, server_key_id, revocation_list_version)
sigma signs (gap_ctx, E_a, E_b)
```

The server signs only adjacent gaps of the current sorted blacklist:

```text
(0,a), (a,b), (b,c), ..., (n,u32::MAX)
```

A client cannot choose `(0,u32::MAX)` unless the current server actually signed that exact broad gap. If the client reuses a broad signature from an older list, it fails because the verifier checks the proof under the current `gap_ctx`.

A blacklisted user with `Emax = b` also fails because both adjacent gaps are open intervals:

```text
(a,b): requires a < Emax < b
(b,c): requires b < Emax < c
```

So an endpoint value cannot prove non-membership.
