# Revocation gap security notes

The revocation proof proves non-membership of the hidden token expiry/handle `Emax` in the server's current blacklist.

Server side:

1. Sort and deduplicate the blacklist.
2. Treat the list as boundary points.
3. Sign only adjacent open gaps: `(0,a)`, `(a,b)`, `(b,c)`, ..., `(n, u32::MAX)`.

Client side:

1. Find the unique adjacent signed gap `(left,right)` containing its hidden `Emax`.
2. Prove `left < Emax < right` in zero knowledge using the v3 signed-gap proof.
3. Attach the public interval `(left,right)` to the wrapper proof.

Verifier side:

1. Reject if the wrapper interval is not exactly one of the current list's adjacent signed gaps.
2. Verify the signed-gap non-membership proof.
3. Verify the cross-curve equality proof ties the proof's `Emax` to the EBUT token's hidden `Emax` commitment.

This prevents the broad-gap attack. A blacklisted user cannot choose `(0,u32::MAX)` or any non-adjacent pair unless the current list actually contains that adjacent gap. If the current blacklist contains an interior revoked value, the broad interval is not a current gap and the wrapper rejects before the ZK proof is accepted.

The current prototype reveals the containing gap interval. This is the robust wrapper-level anti-stale fix. A future fully hidden-gap version should bind the revocation-list root/version directly inside the PS gap signature and keep the interval hidden, but that requires a carefully audited context-bound gap proof.
