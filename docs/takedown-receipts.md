# Takedown Receipts

teabay stores withdrawal and takedown receipt material in
`withdrawals.proof`. The column remains JSONB so each takedown path can carry
the proof that is meaningful for that path without a schema split.

## Receipt Version

All new receipts use:

```text
teabay.withdrawal_receipt.v1
```

## Resource Withdraw

`ak.find.directory.command.withdraw.v1` persists:

- `kind = resource_withdraw`
- `statement`: server receipt facts, including `withdraw_id`, resource,
  reason, `effective_at`, and `acked_at`
- `signed_payload`: the request payload after removing the top-level
  `governance_proof` member (the §8.7.1 unsigned projection)
- `governance_proof`: the original detached JWS proof, including
  `verification_method`, `payload_digest`, `proof_purpose`, `audience`, and
  `jws`
- `verification`: service-side verification metadata

Verification procedure:

1. Confirm `SHA-256(JCS(signed_payload))` equals `governance_proof.payload_digest`.
2. Rebuild the §8.7.1 canonical binding object (`context`
   `ak.directory_governance_request_proof.v1`, the digest, operation id
   `ak.find.directory.command.withdraw.v1`, `resource_id`,
   `verification_method`, `created_at`, `proof_purpose`, `audience`) and
   canonicalize it with the same JSON canonicalization used for ingest proof
   verification.
3. Resolve `governance_proof.verification_method`.
4. Verify the Ed25519 detached JWS over those binding bytes.
5. Confirm `statement.resource_kind`, `statement.resource_id`, and
   `statement.reason` match `signed_payload`. When the request supplied
   `effective_at`, confirm it matches `statement.effective_at`; otherwise the
   statement records the server default.

## Operator Takedown

`/_teabay/admin/takedown` persists:

- `kind = operator_takedown`
- `statement`: signed service receipt facts, including `withdraw_id`,
  resource, reason, `effective_at`, `acked_at`, operator, evidence, notification
  status, and service DID
- `receipt_proof`: detached Ed25519 JWS over `statement`, including the
  verification method, public key, and protected-header `kid`

Operator receipts require:

| Variable | Purpose |
| --- | --- |
| `TEABAY_RECEIPT_SIGNING_KEY_B64` | Base64url or padded base64 raw 32-byte Ed25519 signing key. |
| `TEABAY_RECEIPT_KEY_ID` | Full DID URL recorded in `receipt_proof`; defaults to `$TEABAY_SERVICE_FULL_ID#teabay-receipt-1`. |

If the receipt signing key is missing, operator takedown fails closed instead of
writing an unsigned operator receipt. Local development can use an ephemeral key,
but production should anchor `TEABAY_RECEIPT_KEY_ID` in a DID document or another
operator-controlled key directory.
