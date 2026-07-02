# Tasks for AI/Coding Agent

1. Compile the crate and fix mechanical errors.
2. Replace transferable daily/refund token statements with:
   - `x`, `k`, `balance`, `T`, `Emax`.
3. Extend `RefreshProof`:
   - prove master token signs `(x, cmax, Emax)`;
   - prove `N_T = x * H_epoch(T)`;
   - prove `now <= Emax`;
   - output or verify a BLS commitment to hidden `x` for same-x bridge.
4. Extend `SpendProof`:
   - prove daily/refund token signs `(x, k_cur, cbal, T, Emax)`;
   - prove `m = cbal - s`, `m >= 0`;
   - prove spend-time `now <= Emax`;
   - output or verify a BLS commitment to hidden `x`.
5. Integrate `revocation.rs` into refresh and spend:
   - bind `RevocationContext` into all transcripts;
   - prove hidden `Emax` lies in a signed non-revoked gap.
6. Integrate `same_x_bridge.rs` into upload:
   - BLS commitment must be the one proven by EBUT;
   - Ristretto commitment must be `B_file = x * H_file`.
7. Upgrade `Emax` and revocation gap ranges to `u64` or split into two 32-bit limbs.
8. Replace any `format!("{:?}", cryptographic_object)` transcript input with canonical serialization.
9. Add tests:
   - honest master -> refresh -> spend -> upload succeeds;
   - token transfer without `x` fails;
   - expired `Emax` fails;
   - blacklisted `Emax` fails;
   - unrelated file-binding x fails;
   - file decrypt/reassemble roundtrip succeeds.
