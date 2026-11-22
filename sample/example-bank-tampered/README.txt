PolicyGate evidence export (pg.evidence.export.v1)

Tenant:      example-bank
Export id:   1b8ec90a-c459-4f7d-b6e3-0b30ee2bb5bc (the export itself is a signed record in the signer's own evidence)
Seq range:   1..7
Records:     7

Files
  records.jsonl       one record per line: id, seq, canonical (the signed RFC 8785 body), signature
                      (Ed25519, base64url), kid, body_sha256, prev_hash, decided_at, recorded_at,
                      in_window (false: inside the seq range, outside the requested window; included
                      so the chain has no gaps)
  jwks.json           the public key(s) the records and the manifest are signed with
  manifest.json       tenant, window, seq range, anchor, chain head at export time, file hashes;
                      stored in RFC 8785 canonical form
  manifest.sig        Ed25519 signature (base64url) over the exact bytes of manifest.json
  verify-evidence.py  a copy of the verifier, for convenience
  README.txt          this file

The verifier: take verify-evidence.py from the public repository
  https://github.com/policygate-ai/evidence-verifier
at a tagged release, rather than trust the copy inside this pack. The copy in this pack (like this
README) is NOT covered by the manifest signature: whoever made the pack could have changed it.
It needs Python 3.11 or newer and the pinned dependencies listed in that repository:

  python3 -m pip install --require-hashes -r requirements-verify.txt

The signer's key: the pack carries its own public keys, so on its own it only proves that whoever
made it holds the key inside it. Obtain the signer's key id (kid, an RFC 7638 thumbprint) by a
channel you trust (from the signer directly, or GET /v1/evidence/keys on the deployment) and pin it:

  python3 verify-evidence.py --input <this .zip> --expect-kid <the signer's kid>
  # or, with the signer's public keys saved as a JWKS file:
  python3 verify-evidence.py --input <this .zip> --keys-file signer-keys.json
  # or, unpacked:
  unzip <this .zip> -d pack && python3 verify-evidence.py --input pack --expect-kid <kid>
  # the audit form (anchors required; see Anchors below for tsa-roots.json):
  python3 verify-evidence.py --input <this .zip> --expect-kid <kid> --tsa-roots tsa-roots.json \
      --require-anchors --anchored-since <date anchoring started, RFC 3339>

The --anchored-since date must come from the organisation that runs PolicyGate, through a separate
channel (never from this pack).

Exit 0 and a line starting with "OK:" means: manifest.sig is valid, the files match the manifest's
hashes, every record's signature and sha256(canonical) hold, seq is contiguous from the anchor with
every prev_hash linking to the previous record, and the chain head matches where it was exported.
Without --expect-kid or --keys-file the next line says KEY NOT PINNED: the pack was checked only
against its own key. With a pin, a pack signed by any other key fails. Anything else prints FAIL
lines, the first problem first, and exits non-zero.

Anchors (present when the deployment anchors its evidence with RFC 3161 time-stamp authorities)
  anchors/statements.jsonl  anchor statements, each naming the previous one's SHA-256, signed
                            with the evidence key; a time-stamp authority (TSA) signed the
                            SHA-256 of each
  anchors/proofs.jsonl      this tenant's leaf (hashed tenant id, seq, head hash) and its Merkle
                            inclusion proof per anchor; no other tenant's data
  anchors/tokens/*.tsr      the TSA responses, without certificate chains
  anchors/tsa-certs/*.der   the TSA certificates, once each: intermediates only, never trusted
                            as roots

Checking anchors needs the TSA roots YOU trust, as a file of SubjectPublicKeyInfo SHA-256 pins:

  {"format": "pg.tsa-roots.v1", "roots": [{"name": "<tsa>", "spki_sha256": "<64 hex>",
   "policy_oids": ["<the TSA's policy OID>"]}]}

Obtain each root from the TSA's own publication and compute its pin yourself:

  openssl x509 -in tsa-root.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum

Roots inside this pack are never trusted. Then:

  python3 verify-evidence.py --input <this .zip> --expect-kid <kid> --tsa-roots tsa-roots.json
  python3 verify-evidence.py --input <this .zip> --expect-kid <kid> --tsa-roots tsa-roots.json \
      --require-anchors --anchored-since <when the signer started anchoring, RFC 3339>

ANCHORED: seq a..b covered by <tsa> at <time> (anchor n): those records existed, exactly as here,
at that time, signed by an outside party; rewriting or deleting them since is detectable.
NOT YET ANCHORED: the newest records, recorded after the last anchor in this pack.
ANCHOR CHECKED, RECORDS FAILED: the anchor verifies, but a record in its range failed its own
checks (see the FAIL lines).
With --require-anchors --anchored-since D, every record whose signed created_at is at or after D
must be covered by an anchor in this pack, except the newest records: those may wait for the next
anchor only if recorded before T + 10 min + 15 min (--anchor-interval, --anchor-grace), T being the
TSA time of the latest valid anchor in this pack (or D when there is none). Leaving anchors out of
a pack therefore fails; the failure names the first uncovered seq.
--previous-pack <older.zip> names the exact first record that differs from a pack you kept.

Agent payments: was an observed x402 payment covered by a policy decision? Pass the PAYMENT-SIGNATURE
header value (or @file holding it):

  python3 verify-evidence.py --input <this .zip> --expect-kid <kid> \
      --match-payment @payment-signature.txt

MATCH names the payment.sign record (id, seq) whose authorization it is, with its signature
recovering that record's payer, and (with --tsa-roots) whether that record is ANCHORED.
NO MATCH: no decision in this pack covers it.
