# Hidden-gap revocation binding fix

This patch fixes two separate issues in the previous hidden-gap revocation prototype.

## 1. BLS commitment orientation

The v3 cross-curve equality gadget was committing in BLS as:

```text
C_B = value * G + blinder * H
```

but the equality response equations were using the opposite order in one place. The patch makes the convention explicit everywhere:

```text
C_B = value * value_base + blinder * blind_base
```

and verifies with:

```text
value_base * z_value + blind_base * z_blinder
```

## 2. EBUT Emax commitment bases

Refresh/spend already prove an EBUT-side expiry commitment:

```text
C_delta = (Emax - now) * h5 + r_delta * h0
C_Emax = C_delta + now * h5 = Emax * h5 + r_delta * h0
```

The previous revocation wrapper accidentally generated the non-membership proof using the standalone v3 bases, then verified against the EBUT `(h5,h0)` commitment. That cannot verify and, more importantly, would not be the correct binding.

The patch parameterizes the v3 gap/equality proof over BLS Pedersen bases. Refresh/spend revocation now proves and verifies using exactly:

```text
value_base = generators.h[5]
blind_base = generators.h[0]
```

So the hidden revocation proof is tied to the exact `Emax` already proven inside the EBUT refresh/spend proof, without revealing the gap endpoints.

## Privacy/security

The containing gap `(Ea,Eb)` is still not revealed. Stale broad gaps are rejected because the gap signature is bound to:

```text
H(app_id, policy_id, server_key_id, revocation_list_version)
```

and the verifier checks under the current context.
