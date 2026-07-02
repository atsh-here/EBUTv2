# Non-transferable Emax revocation integration

This patch completes the intended chain:

```text
registered user key x
  -> master token signs (x, c_max, Emax)
  -> daily token signs (x, k_daily, c_max, T, Emax)
  -> refund token signs (x, k_new, m, T, Emax)
  -> redemption file key X_f = x B_f
```

It also adds a server signed-gap revocation list for hidden `Emax` non-membership.

## Emax carry-forward

The code already carried `Emax` through master, refresh/daily, and spend/refund proofs using `h5`:

- master issuance signs the committed message containing `x`, `c_max`, and `Emax`;
- refresh carries `x` and `Emax` into the daily-token commitment;
- spend carries `x` and `Emax` into the refund-token commitment;
- spend and refresh both expose an expiry-delta commitment `c_delta = (Emax-now)*h5 + r_delta*h0`.

This patch exposes `SpendClient::r_delta`, which was required for the client to prove revocation non-membership against the same hidden `Emax` already proven in the spend proof.

## Revocation list model

The server starts with a blacklist:

```text
B = {E_1, E_2, ..., E_n}
```

It sorts and deduplicates it:

```text
E_1 < E_2 < ... < E_n
```

Then it signs every non-empty open gap:

```text
(0, E_1), (E_1, E_2), ..., (E_n, u64::MAX)
```

Each signature is context-bound to:

```text
app_id, policy_id, server_key_id, revocation_list_version
```

A client with hidden `Emax` finds the unique open interval `(ea, eb)` such that:

```text
ea < Emax < eb
```

and proves in zero knowledge:

```text
Emax is committed in EBUT as Emax*h5 + r*h0
Emax is committed in Ristretto as Emax*GV + r1*G1
ea < Emax < eb
server signed the gap (ea, eb, context)
```

If `Emax` is blacklisted, it is an endpoint, not inside any open gap, so proof creation fails. A forged proof also fails verification.

## New API

- `SignedRevocationList::sign_blacklist(ctx, server_sk, blacklist)`
- `SignedRevocationList::find_gap(emax)`
- `SignedRevocationList::prove_emax(...)`
- `SignedRevocationList::prove_refresh_client(...)`
- `SignedRevocationList::prove_spend_client(...)`
- `verify_refresh_not_revoked_from_client_proof(...)`
- `verify_spend_not_revoked_from_client_proof(...)`

## Tests added

- sorted blacklist and blacklisted endpoint rejection;
- direct signed-gap proof verification;
- refresh proof revocation binding;
- spend proof revocation binding;
- blacklisted `Emax` fails for both refresh and spend revocation proof creation.
