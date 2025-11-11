# Identity Attestations

Zero-state identity (ZSI) submissions trigger a sequence of on-chain actions once the
ledger accepts an attested request:

1. **Account activation** – the attested declaration is verified, the new identity
   account is instantiated, and the public-key commitment is written to the identity
   tree. The account’s reputation profile is marked as validated so that subsequent
   activity (timetokes, consensus participation, etc.) can accrue reputation.
2. **Witness emission** – the ledger records a `ZsiWitness` and matching
   `ReputationWitness` in the module witness bundle. These witnesses capture the full
   approval set (validator addresses, signatures, and timestamps) that authorised the
   attestation so downstream consumers can audit which validators endorsed the
   registration.
3. **Slashing on bad attestations** – if the attestation bundle includes malformed
   votes (e.g. signatures that fail verification or votes referencing an unexpected
   block/height), the offending validators are slashed with the `InvalidVote` reason
   before the identity is finalised. The slashing log records the validator address
   and penalty so operators can trace punitive actions back to the faulty
   attestation.

These responses ensure that accepted identities are auditable end-to-end: the account
state reflects the validated declaration, module witnesses expose the exact
approvals, and any validators that attempted to attest with bad votes are
automatically penalised.
