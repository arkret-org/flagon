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

`ck.find.directory.withdraw` persists:

- `kind = resource_withdraw`
- `statement`: server receipt facts, including `withdraw_id`, resource,
  reason, `effective_at`, and `acked_at`
- `signed_payload`: the parsed request payload after removing
  `governance_proof.jws`
- `governance_proof`: the original detached JWS proof, including
  `verification_method` and `jws`
- `verification`: service-side verification metadata

Verification procedure:

1. Canonicalize `signed_payload` with the same JSON canonicalization used for
   ingest proof verification.
2. Rebuild the detached JWS signing input from `governance_proof`.
3. Resolve `governance_proof.verification_method`.
4. Verify the Ed25519 signature.
5. Confirm `statement.resource_kind`, `statement.resource_id`, and
   `statement.reason` match `signed_payload`. When the request supplied
   `effective_at`, confirm it matches `statement.effective_at`; otherwise the
   statement records the server default.

## Operator Takedown

`/_cokret/local/admin/takedown` persists:

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
| `TEABAY_RECEIPT_KEY_ID` | Verification method recorded in `receipt_proof`; defaults to `$TEABAY_SERVICE_DID#teabay-receipt-1`. |

If the receipt signing key is missing, operator takedown fails closed instead of
writing an unsigned operator receipt. Local development can use an ephemeral key,
but production should anchor `TEABAY_RECEIPT_KEY_ID` in a DID document or another
operator-controlled key directory.
