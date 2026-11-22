# PolicyGate evidence pack format and verification

Version 1.

This document describes the evidence pack format `pg.evidence.export.v1` and how the reference verifier,
`verify-evidence.py`, checks it. It is written from the reference verifier and from the code that writes packs. It
aims to be precise enough to write an independent verifier without reading `verify-evidence.py`.

Where this document and the reference verifier disagree, packs are checked today by the reference verifier's
behaviour, and the difference is a defect in one of the two. Security problems are reported privately, through
GitHub private vulnerability reporting on the repository that publishes this document.

Where a behaviour is marked **not specified**, a pack that depends on it is outside this specification. The text
then says what the reference verifier does, so that an independent verifier can match it if it wants to. A correct
pack from the signer never depends on such behaviour.

## 1. Terms and conventions

- **Signer**: one PolicyGate deployment. PolicyGate is self-hosted, so the signer runs in the infrastructure of the
  organisation that operates it.
- **Tenant**: a namespace inside a deployment. Each tenant has its own chain of records.
- **Record**: one signed decision, one line of `records.jsonl`. **seq**: its position in the tenant's chain, from 1.
- **Start hash**: the `prev_hash` of the first record in a pack. The manifest stores it in the field named `anchor`.
  In this document the word "anchor" never means this field: the field is written `anchor` in code font, or called
  the start hash.
- **Anchor**: an anchor statement (section 6.2) together with the RFC 3161 time-stamp tokens for it. Anchors are
  numbered `anchor_seq` 1, 2, 3, ... across the whole deployment. An anchor **covers** a record of the pack when the
  record's seq is inside a range that the coverage step (section 7.6, step 8.14) assigns to it. The verifier prints
  such a range as `ANCHORED`, or as `ANCHOR CHECKED, RECORDS FAILED` when a record in it failed its own checks
  (section 8).
- **TSA**: an RFC 3161 time-stamp authority. **Token**: one TSA response file.
- **Pin**: a value the user supplies and the verifier trusts: a key id (section 3.1) or a TSA root (section 6.6).
- **hex**: lowercase hexadecimal, unless a step says that other forms are accepted.
- **base64url**: RFC 4648 §5 alphabet, written without `=` padding. When decoding, the reference verifier adds
  missing padding and uses Python's `base64.urlsafe_b64decode`, which ignores characters outside the alphabet. Such
  input is **not specified**.
- **JCS**: the JSON Canonicalization Scheme of RFC 8785. The signer writes JCS text. A verifier never needs to
  produce JCS from parsed JSON: every signature and hash is checked over the bytes exactly as they are in the pack.
  The exceptions are a fixed template (the key thumbprint, section 3) and the payment authorization hash (section
  7.5).
- **SHA-256(x)** is the 32-byte digest; "its hex" is the 64-character lowercase hex form.
- **Times.** The signer writes UTC. `created_at` values use `YYYY-MM-DDTHH:MM:SS.mmmZ` (milliseconds); `decided_at`,
  `recorded_at` and the export window use `YYYY-MM-DDTHH:MM:SS.uuuuuuZ` (microseconds). The verifier does **not**
  check these formats. Section 9.2 says where and how it reads times.
- **Message**: a quoted message is the text the verifier prints after `FAIL: `. `<kind>` in a message is one of
  `null`, `a boolean`, `a number`, `a string`, `an array`, `an object`. Values from the pack that appear in messages
  are shortened to one line of printable ASCII, at most 160 characters; some appear in Python `repr` form (for
  example `'abc'` or `{'seq': 3}`).

## 2. Files in a pack

A pack is a zip file. The verifier also accepts a directory that holds the same files.

| Path | Required | Covered by the manifest | Content |
|---|---|---|---|
| `records.jsonl` | yes | yes (sha256) | the records, one JSON object per line |
| `jwks.json` | yes | yes (sha256) | the public keys of the signer |
| `manifest.json` | yes | signed by `manifest.sig` | what the pack holds, with file hashes |
| `manifest.sig` | yes | no (it is the signature) | Ed25519 signature over `manifest.json` |
| `anchors/statements.jsonl` | if anchored | yes (sha256) | anchor statements |
| `anchors/proofs.jsonl` | if anchored | yes (sha256) | this tenant's Merkle leaf and inclusion proof per anchor |
| `anchors/tokens/<anchor_seq>-<tsa>.tsr` | if anchored | yes (sha256) | RFC 3161 `TimeStampResp`, DER |
| `anchors/tsa-certs/<sha256>.der` | if anchored | yes (sha256) | TSA certificates, DER; the name is the hex SHA-256 of the DER |
| `verify-evidence.py` | no | **no** | a copy of the verifier, for convenience |
| `README.txt` | no | **no** | a short description of the pack |

The signer writes the zip entries in this order: `records.jsonl`, `jwks.json`, the `anchors/` files, `manifest.json`,
`manifest.sig`, `verify-evidence.py`, `README.txt`. The order has no meaning for verification.

`verify-evidence.py` and `README.txt` are not covered by any signature or hash. Whoever made the pack could have
changed them.

The reference verifier reads only the four required files and the files whose path starts with `anchors/` (zip
entries ending in `/` are skipped). It ignores everything else, but applies its input limits (section 9.1) to every
entry of a zip.

**What the signer's packs contain in practice.** These facts hold for the signer's code and the sample pack. They
are not checks.

- The signer asks TSAs for tokens without certificates (`certReq` false), unless it is configured to always ask, or
  does not yet know that TSA's certificates. If a stored token carries certificates, the pack holds a copy without
  them (section 6.1). The signer certificate and the chain to the root then come only from `anchors/tsa-certs/`,
  which also holds the root certificate.
- The sample's two tokens are from FreeTSA. They are signed with ECDSA over SHA-512, identify the signer by issuer
  and serial number, carry an ESS `signingCertificate` attribute (version 1, SHA-1) and a `signingTime` attribute,
  hold no certificates, and name the TSA policy OID `1.2.3.4.1`. Their TSTInfo carries a nonce. The signer
  certificate has an EC key and is issued by the FreeTSA root, an RSA certificate authority.
- The first statement in a pack names, in `prev_statement_sha256`, the statement of the anchor before it. That
  anchor is usually not in the pack (in the sample, anchor 358 names anchor 357). So one pack cannot check the
  statement chain back to anchor 1; only consecutive statements inside the pack are checked against each other.

## 3. Keys: `jwks.json`

A JSON Web Key Set: `{"keys": [ ... ]}`. Each Ed25519 key is a JWK (RFC 8037):

```json
{"kty": "OKP", "crv": "Ed25519", "x": "<32-byte public key, base64url>", "kid": "<thumbprint>",
 "use": "sig", "alg": "EdDSA", "status": "active"}
```

- `status` is `active` for the key that signs now and `retired` for an earlier key. A retired key may also carry
  `not_after`. The verifier ignores `use`, `alg`, `status` and `not_after`.
- The signer puts the active key first, then each retired key that signed a record or an anchor statement in the
  pack.
- **Key id.** `kid` is the RFC 7638 thumbprint: the base64url (no padding) of SHA-256 of the UTF-8 bytes of exactly

  ```
  {"crv":"Ed25519","kty":"OKP","x":"<x>"}
  ```

  where `<x>` is the `x` string as it appears in the JWK. A kid is therefore 43 characters from `A-Z a-z 0-9 - _`.

How the reference verifier loads keys (any failure stops verification, with `jwks.json: ` before the message):

1. The document must be an object whose `keys`, if present, is an array (`not a JWKS ({"keys": [...]})`). Every
   element must be an object (`a JWKS key is <kind>, not an object`).
2. An element whose `kty` is not `OKP` or whose `crv` is not `Ed25519` is skipped. Its other members are not
   checked.
3. `x` must be a string (`a JWKS key's x is <kind>, not a string`). The thumbprint is computed over `x` as written;
   `kid` must equal it (`JWKS kid <kid> is not the RFC 7638 thumbprint '<thumbprint>'`).
4. `x` is base64url-decoded and must be 32 bytes; otherwise the crypto library's error text is the message.
5. At least one Ed25519 key must remain (`JWKS contains no Ed25519 keys`).

**Not specified:** `x` written with `=` padding; the reference verifier accepts it when `kid` is the thumbprint of
the padded string. **Duplicate kids**: a kid is the hash of `x`, so two keys with the same kid have the same `x`;
the reference verifier keeps the last.

### 3.1 Pinning

A pack carries its own public keys. On its own, it proves only that whoever made it holds the private key that
matches `jwks.json`. A pack forged end to end with a new key verifies, unless the verifier is told which key to
expect. The verifier takes this from the user, never from the pack:

- `--expect-kid KID` (repeatable): the manifest, every record and every anchor statement line must name a kid that
  is one of these. Each value must match `[A-Za-z0-9_-]{43}`; else a usage error (exit 2). A kid can start with `-`.
  Both `--expect-kid KID` and `--expect-kid=KID` work: before parsing, the verifier joins `--expect-kid` with the
  argument after it, up to a `--` argument.
- `--keys-file FILE`: a JWKS obtained out of band. It must be a regular file (not a symlink) of at most 1 MiB, of the
  form `{"keys": [...]}`, loaded as above; else exit 2. Every kid the pack uses must be in this file, and the pack's
  key for that kid must have the same 32 bytes.

If both are given, a kid must pass both. Without either, a valid pack still exits 0, and the verifier prints a
`KEY NOT PINNED` line (section 8).

The pin failure reasons, written `<why>` in messages below, are: `the kid is <kind>, not a string`;
`kid '<kid>' is not one of --expect-kid`; `kid '<kid>' is not in --keys-file <path>`;
`the pack's key '<kid>' differs from the one in --keys-file <path>`.

## 4. Records: `records.jsonl`

UTF-8. The signer writes one JSON object per line, each line ended by `\n` (no `\r`), in seq order.

**How the reference verifier splits the file.** It splits the bytes on `\n`. Lines are numbered from 1 in that
split, counting every line, including empty ones. An empty line (zero bytes, such as the one after the final `\n`)
is skipped. A missing final `\n` makes no difference. **Not specified:** a line ending in `\r\n` (the reference
verifier accepts it, because JSON allows `\r` as whitespace) and a line of only spaces or tabs (the reference
verifier reports `records.jsonl line <n>: not a valid record (<why>)`). The file hash in the manifest covers the
exact bytes either way.

### 4.1 The record line (envelope)

| Field | Type | Meaning | Signed |
|---|---|---|---|
| `id` | string | record id (a UUID) | also inside `canonical` |
| `seq` | integer | position in the tenant's chain, from 1 | also inside `canonical` |
| `canonical` | string | the signed body, as JCS text | the signed bytes |
| `signature` | string | Ed25519 signature over the UTF-8 bytes of `canonical`, base64url | — |
| `kid` | string | the kid of the signing key | no |
| `body_sha256` | string | hex SHA-256 of the UTF-8 bytes of `canonical` | no (recomputed) |
| `prev_hash` | string | `body_sha256` of the previous record; 64 zeros at seq 1 | also inside `canonical` |
| `decided_at` | string | when the decision was made (see below) | **no** |
| `recorded_at` | string | when the signer recorded it: the same instant as the body's `created_at` | **no** |
| `in_window` | boolean | false when the record lies outside the requested time window (section 5) | **no** |

`decided_at` is `payload.decision_time` for `edge_authz` records when that value matches `YYYY-MM-DDTHH:MM:SS`, an
optional fraction of 1 to 9 digits, and `Z` or `+HH:MM`/`-HH:MM`, and parses as a time. For every other record, or
when the value does not match, it is the body's `created_at`. The signer's database keeps microseconds, so a
`decision_time` with nanoseconds appears rounded to microseconds (in the sample, `15:22:58.838402562Z` becomes
`15:22:58.838403Z`).

The verifier does not read `decided_at`, `recorded_at` or `in_window`, and does not check records against the
manifest's `window` or `in_window_count`.

A **valid record line** is a JSON object with all of `id`, `seq`, `canonical`, `signature`, `kid`, `body_sha256`
and `prev_hash`, where `seq` is an integer (section 7.1) and the other six are strings. Other members are ignored.
Section 7.4 checks the contents.

### 4.2 The signed body (`canonical`)

`canonical` is the JCS text of this object (shown in readable order; JCS sorts the keys):

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | always `pg.evidence.v1` |
| `id` | string | record id, equal to the envelope `id` |
| `tenant_id` | string | the tenant, equal to the manifest's `tenant` |
| `decision_type` | string | kind of decision; see below |
| `subject` | string or null | who or what the decision is about |
| `outcome` | string | the result, for example `allow`, `deny`, `applied` |
| `reasons` | array of strings | machine-readable reasons |
| `policy` | object | `pack_version`, `bundle_revision`, `decision_id`: each a string or null |
| `input_sha256` | string or null | hex SHA-256 of the decision input, when the input itself is not stored |
| `payload` | object | fields that depend on `decision_type` |
| `created_at` | string | when the signer recorded it, milliseconds, UTC; must parse as a time with a zone |
| `seq` | integer | equal to the envelope `seq` |
| `prev_hash` | string | equal to the envelope `prev_hash` |

**Signed bytes.** The signer signs, and hashes, the UTF-8 encoding of `canonical`. To verify, take the `canonical`
string as decoded from the JSON line, encode it as UTF-8, and check `hex(SHA-256(bytes)) == body_sha256` and the
Ed25519 signature over the same bytes.

The verifier checks only `schema`, `id`, `tenant_id`, `seq`, `prev_hash` and `created_at` of the body (section 7.4),
and reads `created_at` again for anchors (sections 7.6 to 7.8). It does not interpret `decision_type`, `subject`,
`outcome`, `reasons`, `policy`, `input_sha256` or `payload`, except for payment records (section 7.5). The rest of this
section describes what the signer writes into them, for the record types a tenant chain can hold.

#### `edge_authz`: a request decided by the policy engine at the edge proxy

- `tenant_id` and `subject` come from the claims of the caller's verified JWT, at locations set in the deployment's
  configuration. A request without a verified tenant is recorded in a chain the configuration names for
  unauthenticated requests. `subject` is null when no claim is found.
- `outcome` is `allow` or `deny`, from the policy result.
- `reasons`: `deny_reason=<value>` and `deny_category=<value>` when the policy result carries them; otherwise
  `x-policy-reason=<value>` and `x-policy-decision=<value>`, each only when present.
- `policy.pack_version` is the policy decision path as the policy engine logged it, `policy.bundle_revision` the
  revision of the policy bundle, and `policy.decision_id` the policy engine's decision id.
- `input_sha256` is the hex SHA-256 of the JCS text of the decision input, after removing, at any depth, every
  object member whose name is, compared case-insensitively, `authorization`, `cookie`, `set-cookie`, `x-api-key` or
  `proxy-authorization`. The input itself is not stored. It is null when the event has no input. If the input
  cannot be put in JCS form, `input_sha256` is null and the payload has `input_hash_error: "not_canonicalizable"`.
- `payload` holds only these members, each only when the source value exists:
  - `method`, `host`: from the request; `path`: from the request, without the query string. Each is cut to at most
    2048 characters.
  - `model`: the model the policy reported, if it matches `[A-Za-z0-9._:/-]{1,128}`; otherwise `model_invalid: true`.
  - `rate_limit`: `{status, limit_rpm, metered}` from the policy's rate-limit result. `status` is `ok`, `over`,
    `unavailable` or `no_tenant`; `limit_rpm` an integer from 1 to 100000, left out when the policy reported none;
    `metered` is true only for `ok` and `over`. An invalid result gives `rate_limit_invalid: true` instead.
  - `agent_id`: from the verified JWT's `agent_id` claim, if it matches `[a-z0-9][a-z0-9._-]{0,63}`; otherwise
    `agent_id_invalid: true`.
  - `decision_time`: the policy engine's timestamp of the decision (at most 2048 characters).
  - `provider_id`: on allowed requests only, the routed provider's id if it is a lowercase canonical UUID; otherwise
    `provider_id_invalid: true`.
  - `input_hash_error`: see `input_sha256`.

#### `admin_change`: a change made through the administration interface

- `outcome` is `applied`. `subject` is the administrator's `sub` claim, or `_admin_auth_disabled` when the
  deployment runs without administrator authentication.
- `reasons` is one element, `<target kind>.<action>`, for example `tenant.create`.
- `policy` is `{"pack_version": "admin_api", "bundle_revision": null, "decision_id": <the request's trace id, or
  null>}`. `input_sha256` is null.
- `payload`: `action` (`create`, `update` or `delete`); fields that identify the target, for example `tenant_uuid`
  and `slug`; `auth_enabled` (boolean); with authentication on, `actor`: `{sub, iss, roles}` of the administrator's
  verified token; `changes`: an array of `{field, before, after}`, with `before` null on create and `after` null on
  delete. Free-form values, such as tenant metadata, appear only as a SHA-256 of their JCS text (in the sample, the
  field `metadata_sha256`). Some changes add further payload members; they are **not specified**.

#### `agent_spend`: agent payments

The payload is **not specified** in version 1. The sample holds no such record. Section 7.5 lists the members the
reference verifier reads in `payment.sign` records and the checks it makes.

#### Other values

The signer also writes `evidence_export` and `evidence_anchor` records, into its own system chain, not into a
tenant's chain. Other values of `decision_type` are **not specified**.

### 4.3 The hash chain

Each tenant has one chain. Records get `seq` 1, 2, 3, ... with no gaps.

- The `prev_hash` of seq 1 is 64 zeros, called the genesis value.
- The `prev_hash` of seq n > 1 is the `body_sha256` of seq n-1.

`prev_hash` is inside the signed body, so each record commits to the one before it. Changing, removing or
reordering a record breaks the link of the record after it, unless every later record is re-signed, which needs the
private key.

A pack may start after seq 1. Its start hash is then the `body_sha256` of a record that is not in the pack. Inside
one pack it can only be checked against the manifest; `--previous-pack` (section 7.7) or an anchor can tie it to an
earlier pack or to a timestamp.

## 5. The manifest: `manifest.json` and `manifest.sig`

`manifest.json` is the JCS text of one object, UTF-8. `manifest.sig` is the base64url Ed25519 signature over the
exact bytes of `manifest.json`, in ASCII, followed by `\n`. The verifier decodes `manifest.sig` as ASCII, strips
surrounding whitespace, and verifies over the bytes of `manifest.json` as they are. It does not re-canonicalize.

Fields, in the order the signer builds them:

| Field | Type checked | Meaning | Use by the verifier |
|---|---|---|---|
| `format` | must be equal | `pg.evidence.export.v1` | step 7.3.6 |
| `export_id` | no | id of this export (a UUID) | printed |
| `tenant` | non-empty string | the tenant | equals each body's `tenant_id`; anchor leaves |
| `window` | object or null; `from`, `to` string or null | the requested decision-time window | none |
| `seq_range` | object or null; `first`, `last` integers | the seq range in `records.jsonl`; null for an empty pack | yes |
| `record_count` | integer | number of records in `records.jsonl` | yes |
| `in_window_count` | no | number of records with `in_window` true | none |
| `anchor` | string or null | the start hash (64 zeros when `first` is 1); null for an empty pack | yes |
| `chain_head` | object or null; `seq` integer, `hash` string | the tenant's chain head when the pack was made | yes |
| `created_at` | string | when the pack was made, milliseconds | type only (step 7.3.7); no check uses its value |
| `shield` | no | build information of the signing service: `version` (its version string) and `commit` (the source revision it was built from) | none |
| `bundle_revisions` | no | the distinct `policy.bundle_revision` values of the records, sorted | none |
| `files` | object; each value an object with a string `sha256` | `{path: {"sha256": hex, "bytes": integer}}` | step 7.3 |
| `anchoring` | object or null | section 6.1; `{"present": false}` when the pack has no anchors | yes |
| `signing_kid` | string | kid of the key that signed `manifest.sig` | yes |
| `exported_by` | no | `credential` (`read_token` or `jwt`) and `sub` (the caller's subject, or `evidence-read-token` for the read token) | none |

The signer lists in `files` exactly `records.jsonl`, `jwks.json` and every `anchors/` file. The verifier never
checks `bytes`.

**Which records a pack holds.** The signer takes the tenant's records whose `decided_at` lies in the window, and
exports the contiguous seq range from the first to the last of them, so the chain has no gaps. Records in that range
but outside the window are included with `in_window: false`. With anchoring, the range may be extended to the head
seq of the first anchor at or after its last record (if the pack stays within the signer's size limit), so the end
of the range can be shown as covered.

`chain_head` is the tenant's head when the pack was made: the seq and `body_sha256` of its newest record. It can be
beyond `seq_range.last` when later records exist outside the window. The signer creates the head in the same
transaction as the tenant's first record, so `chain_head` is null only when the tenant has no record.

**The export is itself recorded.** Before it sends the pack, the signer appends a signed `evidence_export` record to
the deployment's own system chain. It holds the tenant, window, seq range, record count, and the SHA-256 of
`records.jsonl` and of `manifest.json`. That chain is not part of the pack.

## 6. Anchors

A deployment may anchor its evidence. At intervals, the signer builds a Merkle tree over the current chain heads of
all its tenants. It writes an anchor statement that holds the tree's root, signs the statement with the evidence
key, and has one or more TSAs timestamp the statement's SHA-256. The TSA sees only that hash.

An anchor shows that, at the TSA's time, the tenant's chain had a given head: a seq and the `body_sha256` of that
record. Each record links to the previous one, so the anchor fixes the chain of `body_sha256` values up to that
seq. It fixes the record contents only together with the record checks of section 7.4.

### 6.1 The manifest's `anchoring` object

When `present` is true:

| Field | Type checked | Meaning |
|---|---|---|
| `present` | boolean (when the member exists) | true |
| `tenant_sha256` | no | hex SHA-256 of `"pg.anchor.tenant.v1:" + tenant` (UTF-8) |
| `first_anchor_seq`, `last_anchor_seq` | integers | the first and last anchor in `anchors/statements.jsonl` |
| `anchors` | no | number of statements |
| `proofs` | no | number of proof lines |
| `tokens` | array or null; each element an object with integer `anchor_seq`, string `file`, string or null `tsa` | one object per token: `anchor_seq`, `tsa` (the TSA's name in the signer's configuration), `file` (path in the pack), `response_sha256` (hex SHA-256 of the response bytes exactly as the TSA returned them), `certificates_removed` (boolean) |
| `tsa_certs` | no | hex SHA-256 of each certificate in `anchors/tsa-certs/` |

The verifier uses `present`, `first_anchor_seq`, `last_anchor_seq` and, in `tokens`, `anchor_seq`, `file` and `tsa`
(in messages). It does not use the other members.

The signer stores each token as received. If a stored token carries certificates, the pack holds a copy re-encoded
without the SignedData `certificates` field (`certificates_removed: true`). This does not touch the signed part of
the token, so it still verifies; `response_sha256` stays the hash of the original. The certificates are put once
each in `anchors/tsa-certs/`.

The pack holds the contiguous run of anchors from the first one that covers a record of the pack to the first one
that covers its last record. If no anchor covers the last record yet, the run goes to the latest anchor. If none
covers any record of the pack, it holds only the latest anchor.

### 6.2 Statements: `anchors/statements.jsonl`

One JSON object per line:

| Field | Type checked | Meaning |
|---|---|---|
| `anchor_seq` | integer | the anchor's number |
| `statement` | string | the statement, as JCS text |
| `statement_sha256` | string | hex SHA-256 of the UTF-8 bytes of `statement` |
| `statement_signature` | string | Ed25519 signature over the UTF-8 bytes of `statement`, base64url |
| `kid` | string | the kid of the key that made `statement_signature` |

The statement object:

| Field | Checked | Meaning |
|---|---|---|
| `schema` | must equal `pg.anchor.v1` | |
| `anchor_seq` | integer, equal to the line's | the anchor's number |
| `prev_statement_sha256` | string | `statement_sha256` of anchor `anchor_seq - 1`; 64 zeros for anchor 1 |
| `merkle_root` | 64 lowercase hex | root of the tree (section 6.4) |
| `tree_size` | integer | number of leaves, pads included |
| `created_at` | string that parses as a time with a zone | when the signer made the statement |
| `kid` | must equal the line's `kid` | the kid of the signing key |

The statement holds hashes and counters only, no tenant names. Statements form their own hash chain through
`prev_statement_sha256`.

### 6.3 Proofs: `anchors/proofs.jsonl`

One JSON object per anchor in which this tenant has a leaf:

| Field | Type checked | Meaning |
|---|---|---|
| `anchor_seq` | integer | the anchor |
| `leaf_index` | integer | position of the tenant's leaf, from 0 |
| `tree_size` | integer | equal to the statement's `tree_size` |
| `leaf_data` | string | the leaf, as JCS text |
| `path` | array of strings | the inclusion proof: hex sibling hashes, from the leaf's sibling up to the root |

`leaf_data` is the JCS text of:

```json
{"head_hash": "<body_sha256 of the head record>", "seq": <head seq>, "tenant_sha256": "<hex>", "v": 1}
```

`tenant_sha256` is the hex SHA-256 of the UTF-8 bytes of `pg.anchor.tenant.v1:` followed by the tenant id. Other
tenants' leaves are not in the pack; the path holds only hashes. The reference verifier decodes `path` elements with
Python's `bytes.fromhex`, which also accepts uppercase and spaces between bytes (**not specified**).

### 6.4 The Merkle tree

The tree is the Merkle Tree Hash of RFC 9162 §2.1 (Certificate Transparency 2.0), with SHA-256.

- **Leaves.** One leaf per tenant chain that has at least one record, holding that chain's head when the anchor was
  made. Leaves are sorted by `tenant_sha256` (as hex strings, which is the same as byte order). Then pad leaves are
  added until the number of leaves is a power of two and at least 16. A pad leaf is the JCS text of
  `{"pad": "<32 random bytes, hex>", "v": 1}`. So the tree size reveals only a range of the number of tenants.
- **Leaf hash:** `SHA-256(0x00 || UTF-8(leaf_data))`.
- **Node hash:** `SHA-256(0x01 || left || right)`, where `left` and `right` are 32-byte hashes.
- **Tree hash** of n leaves: for n = 1, the leaf hash. For n > 1, let k be the largest power of two smaller than n;
  the tree hash is the node hash of the tree hash of the first k leaves and the tree hash of the remaining n - k
  leaves. Odd nodes are never duplicated. Because the signer pads to a power of two, every tree it builds is
  complete.
- **Inclusion proof check** (RFC 9162 §2.1.3.2), for leaf hash `h` at index `i` in a tree of size `n` with path
  `p[0..]` and root `r`:

  ```
  if not 0 <= i < n: fail
  fn = i; sn = n - 1; x = h
  for each p in path:
      if sn == 0: fail
      if fn is odd or fn == sn:
          x = node(p, x)
          if fn is even:
              while fn is even and fn != 0: fn >>= 1; sn >>= 1
      else:
          x = node(x, p)
      fn >>= 1; sn >>= 1
  succeed if sn == 0 and x == r
  ```

### 6.5 Time-stamp tokens: `anchors/tokens/*.tsr`

Each file is a DER `TimeStampResp` (RFC 3161) for the SHA-256 of one statement. The verifier checks one token as
follows. Any failure rejects that token; the reason is shown in brackets. Malformed DER anywhere gives
`not a valid time-stamp token (<error type>)`.

1. The response status is `granted` or `grantedWithMods` (`TSA status <status>`).
2. The token is CMS `SignedData` (`token is not CMS SignedData`) and its `eContentType` is `id-ct-TSTInfo`
   (`eContentType is not id-ct-TSTInfo`).
3. The `TSTInfo` message imprint uses SHA-256, and its hash equals the bytes of the statement line's
   `statement_sha256` value as written, decoded from hex, not recomputed from the statement
   (`message imprint is not SHA-256 of this statement`). If that value is not hex, the token fails with Python's
   error text. A `statement_sha256` that does not match the statement is a separate failure (section 7.6).
4. `genTime` and the policy OID are read from `TSTInfo`. The nonce, `accuracy` and `ordering` are not checked.
5. Candidate certificates: those inside the token, in token order, then those in `anchors/tsa-certs/`, in path
   order.
6. There is exactly one `SignerInfo` (`expected one SignerInfo`). The signer certificate is the first candidate whose
   serial number equals the SignerInfo's and whose issuer name, as DER bytes, equals the SignerInfo's issuer; or, if
   the SignerInfo names a subject key identifier, the first candidate with that key identifier
   (`signer certificate not in the token nor in anchors/tsa-certs`).
7. The SignerInfo `digestAlgorithm` is SHA-1, SHA-256, SHA-384 or SHA-512 (`digest algorithm <name> not supported`).
8. The signed attributes hold a `contentType` of `id-ct-TSTInfo` (`signed contentType is not TSTInfo`) and a
   `messageDigest` equal to the digest, with the `digestAlgorithm`, of the TSTInfo DER (the content of the
   `eContent` OCTET STRING) (`messageDigest does not match the TSTInfo (content changed)`). Other attributes, such as
   `signingTime`, are not checked.
9. ESS: if a `signingCertificateV2` attribute is present, the `certHash` of its first `ESSCertIDv2` must equal the
   hash of the signer certificate's DER, with the attribute's hash algorithm (SHA-256 when absent)
   (`ESS signing-certificate-v2 does not name the signer certificate`). There is **no fallback** to version 1 when
   this fails. Otherwise a `signingCertificate` attribute (version 1) must be present, and the `certHash` of its
   first `ESSCertID` must equal the SHA-1 of the signer certificate's DER
   (`ESS signing-certificate does not name the signer certificate`). The `issuerSerial` member is not checked.
   Neither attribute: `no ESS signing-certificate attribute`.
10. The signature is checked over the DER of the signed attributes, with the first byte changed from the `[0]
    IMPLICIT` tag to `0x31` (SET OF), as RFC 5652 §5.4 requires. The algorithm follows the signer certificate's key
    type:
    - RSA: if the SignerInfo `signatureAlgorithm` is RSASSA-PSS, PSS with the hash and salt length from its
      parameters and MGF1 with that same hash; otherwise PKCS#1 v1.5 with the `digestAlgorithm`.
    - EC: ECDSA with the `digestAlgorithm`; the hash named in the `signatureAlgorithm` OID is not compared. The
      signature is a DER `ECDSA-Sig-Value`.
    - Ed25519: pure Ed25519 over the bytes, no prehash.
    - Any other key type: `signer key type not supported`.

    A signature that does not verify: `token signature INVALID`.
11. The signer certificate has an extended key usage extension that is critical and holds exactly
    `id-kp-timeStamping` (`signer has no extended key usage`,
    `signer EKU is not exactly a critical id-kp-timeStamping`).
12. Chain to a pin. Start with `cur` = the signer certificate, and repeat at most 8 times:
    1. `cur` must be valid at `genTime`: `notBefore <= genTime <= notAfter` (`certificate <CN> not valid at genTime`).
    2. Unless `cur` is the signer certificate, it must have a basic constraints extension with `cA` true
       (`<CN> is not a CA`).
    3. If the SHA-256 of `cur`'s DER `SubjectPublicKeyInfo` equals a pinned `spki_sha256`, the chain ends; that pin
       is the root. So a pinned root must be valid at `genTime`, and must be a CA unless it is the signer certificate
       itself. It need not be self-signed, and its own signature is not checked.
    4. Otherwise the next `cur` is the first candidate (in the order of step 5), other than `cur` itself, whose
       subject equals `cur`'s issuer and whose public key verifies `cur`'s signature. Names are equal when they have
       the same attributes with exactly equal values: case-sensitive, string encoding ignored, no other
       normalisation. There is no backtracking to other candidates (`no chain from <CN> to a pinned root
       (--tsa-roots)`).

    After 8 certificates without a pin: `certificate chain too long`. Key usage, path length and name constraints
    are not checked. Revocation is not checked.
13. The token's policy OID must be one of the `policy_oids` of the pinned root that the chain reached
    (`policy <OID> is not pinned for root <name>`).

`<CN>` is the certificate's first common name, or its whole subject if it has none. A token that passes gives
`genTime`, the root's `name` and the signer certificate's common name.

### 6.6 TSA root pins

The verifier takes the root pins from the user with `--tsa-roots FILE`, never from the pack:

```json
{"format": "pg.tsa-roots.v1",
 "roots": [{"name": "<a name>", "spki_sha256": "<64 lowercase hex>", "policy_oids": ["<OID>", "..."]}]}
```

`spki_sha256` is the SHA-256 of the root certificate's DER `SubjectPublicKeyInfo`. Every root needs a non-empty
`name`, a 64-character lowercase hex `spki_sha256` and a non-empty `policy_oids` array. Other members are ignored.
The file is read as JSON (at most 1 MiB) and never hashed as a whole. A malformed file, or one with no roots, is a
usage error (exit 2).

**Checking a root yourself.** Get the root certificate from the authority's own publication, check it against what
the authority publishes about it, then compute the pin:

```
sha256sum root.pem                                                                   # the file, as published
openssl x509 -in root.pem -outform DER | sha256sum                                   # the certificate (DER)
openssl x509 -in root.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum   # the pin
```

For FreeTSA, the root is at `https://freetsa.org/files/cacert.pem`, and FreeTSA's page
`https://freetsa.org/index_en.php` lists the SHA-256 of that file. Checked on 2026-11-21: the file's SHA-256 was
`2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`, which the page lists; its DER SHA-256 was
`a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc`, the same certificate as the sample's
`anchors/tsa-certs/a6379e....der`; and its pin was `52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5`.
The policy OID `1.2.3.4.1` is the value FreeTSA's tokens carry (the sample's TSTInfo names it). It is FreeTSA's own
value, not a placeholder.

## 7. The verification algorithm

This is the order in which `verify-evidence.py --input` checks a pack. Failures are collected; unless a step says
that it stops, checking continues so that every problem is reported.

### 7.1 Reading JSON and comparing values

**Not specified**, for any JSON in a pack: duplicate object members, `NaN`, `Infinity`, `-Infinity`, and numbers
outside the range of a double. The signer never writes them (its JCS rejects them). The reference verifier parses
with Python's `json` module: a duplicate member keeps its last value; `NaN`, `Infinity` and `-Infinity` are accepted
as numbers; a number with a fraction or exponent is a float.

A type check for "integer" rejects booleans and floats (even `1.0`). Where the verifier compares values without
checking their type first, it uses Python equality, in which `true == 1` and `1.0 == 1`. This applies to the signed
body's `seq` (compared with the envelope's integer `seq`) and to the leaf's `v` (compared with 1). **Not
specified:** a body `seq` or a leaf `v` written as `true` or `1.0`; the reference verifier accepts them.

Every JSON text must also respect the limits of section 9.1.

### 7.2 Read the pack

1. Read the zip or the directory. Input over a limit or of an unsafe shape (section 9.1) gives `REJECTED: <why>`;
   an unreadable pack gives `<path>: cannot read pack (<why>)`. Stop.
2. Each of the four required files that is missing gives `<name>: missing from the pack`. Stop.

### 7.3 Keys, manifest, files and records

Each failure in steps 1 to 7 stops verification.

1. Load `jwks.json` (section 3). Failure: `jwks.json: <why>`.
2. Parse `manifest.json` as a JSON object: `manifest.json: not valid JSON (<why>)`; `<why>` is `not an object`
   when it parses to something else.
3. `signing_kid` must be a string (`manifest.json: signing_kid is <kind>, expected a string`) and a kid in
   `jwks.json` (`manifest.sig: signing_kid '<kid>' not in jwks.json`).
4. Verify `manifest.sig` over the bytes of `manifest.json` with that key:
   `manifest.sig: signature INVALID over manifest.json` (also when `manifest.sig` is not ASCII or not base64url).
5. With a pin, `signing_kid` must be pinned: `manifest.sig: the manifest is not signed by a pinned key: <why>`.
6. `format` must be `pg.evidence.export.v1`: `manifest.json: format <value>, expected 'pg.evidence.export.v1'`.
7. Field types. First the top level (section 5): `manifest.json: <field> is <kind>, expected <wanted>`, where
   `<wanted>` is `a non-empty string` (`tenant`), `an object or null` (`seq_range`, `chain_head`, `anchoring`,
   `window`), `an integer` (`record_count`), `a string or null` (`anchor`), `an object` (`files`), `a string`
   (`created_at`). If any fails, all such problems are printed and verification stops. Otherwise the nested fields,
   again all at once:
   - `manifest.json: seq_range.first is <kind>, expected an integer` (and `.last`);
   - `manifest.json: chain_head.seq is <kind>, expected an integer`; `manifest.json: chain_head.hash is <kind>,
     expected a string`;
   - `manifest.json: window.from is <kind>, expected a string` (and `.to`; null is allowed);
   - `manifest.json: files['<name>'] is <kind>, expected an object with a sha256 string`;
   - `manifest.json: anchoring.present is <kind>, expected a boolean`; and, when `present` is true,
     `manifest.json: anchoring.first_anchor_seq is <kind>, expected an integer` (and `last_anchor_seq`),
     `manifest.json: anchoring.tokens is <kind>, expected an array`,
     `manifest.json: anchoring.tokens[<i>] is <kind>, expected an object`,
     `manifest.json: anchoring.tokens[<i>].anchor_seq is <kind>, expected an integer`,
     `manifest.json: anchoring.tokens[<i>].file is <kind>, expected a string`,
     `manifest.json: anchoring.tokens[<i>].tsa is <kind>, expected a string` (null is allowed).

From here on, the manifest is trusted: it is signed and well formed.

8. With a pin, each line of `anchors/statements.jsonl` that is not empty or whitespace (numbered as lines of the
   file) must be JSON (`anchors/statements.jsonl line <n>: not JSON (<why>)`) and name a pinned `kid`
   (`anchors/statements.jsonl line <n>: statement not signed by a pinned key: <why>`). This runs with or without
   `--tsa-roots`.
9. `hex(SHA-256(jwks.json))` must equal `files["jwks.json"].sha256`; a missing entry counts as a mismatch
   (`jwks.json: sha256 <hex> does not match the manifest`).
10. Parse `records.jsonl` (section 4). A line that is not a valid record line gives
    `records.jsonl line <n>: not a valid record (<why>)`, where `<why>` is the JSON error, `not an object (<kind>)`,
    `missing <fields>`, or `<field> is <kind>, expected <wanted>`. Such a line is **left out**: the chain check runs
    on the remaining records only.
11. If `seq_range` is null: the pack must hold no records and `record_count` must be 0
    (`records.jsonl: <n> record(s) but the manifest declares an empty pack`). Else, with `first`, `last` =
    `seq_range`:
    - `first >= 1` and `last >= first` (`manifest.json: bad seq_range <value>`), and there must be records
      (`records.jsonl: no records, the manifest declares seq <first>..<last>`). If either fails, the checks below
      are skipped except the last one.
    - The start hash must be a string of 64 characters; hex is not checked
      (`manifest.json: anchor <value> is not a sha256 hex digest`). If `first` is 1, it must be 64 zeros
      (`manifest.json: anchor of seq 1 must be the genesis hash`).
    - The chain check (section 7.4), starting at seq `first` with the previous hash 64 zeros if `first` is 1, else
      the start hash (or no previous hash, if the start hash failed the length check).
    - The last record's `seq` must equal `last`
      (`records.jsonl: last seq <seq>, the manifest declares <last> (records missing at the end?)`).
    - `chain_head.seq` must be an integer `>= last`
      (`manifest.json: chain_head <value> is before the last exported seq <last>`). If it equals `last`,
      `chain_head.hash` must equal the last record's `body_sha256`
      (`seq <last> (id <id>): body_sha256 is not the manifest's chain_head hash <hash>`).
    - The number of records must equal `record_count`
      (`records.jsonl: <n> record(s), the manifest declares record_count <count>`).
12. `hex(SHA-256(records.jsonl))` must equal `files["records.jsonl"].sha256`; a missing entry counts as a mismatch
    (`records.jsonl: sha256 <hex> does not match the manifest`).
13. Every pack file under `anchors/`, in path order, must be listed in `files`
    (`<path>: in the pack but not declared in the manifest`) with a matching sha256
    (`<path>: sha256 does not match the manifest`). Then every `anchors/` path listed in `files` must be in the pack
    (`<path>: declared in the manifest but missing from the pack`). Entries of `files` other than `records.jsonl`,
    `jwks.json` and `anchors/...` are ignored, whether or not such a file exists. `bytes` is never checked.

### 7.4 The chain check

For each record, in file order, with `expected_seq` starting at `first` and `prev` the previous hash. Messages start
with `seq <n> (id <id>): `.

1. With a pin, the record's `kid` must be pinned: `not signed by a pinned key: <why>`.
2. `seq == expected_seq`; else `expected seq <expected_seq> (gap or reorder)`.
3. `hex(SHA-256(UTF-8(canonical))) == body_sha256`; else `sha256(canonical)=<hex> != body_sha256=<value>`.
4. If there is a previous hash, `prev_hash == prev`; else `prev_hash <value> does not link to previous body_sha256
   <prev>`.
5. The `kid` is in `jwks.json` (`unknown kid '<kid>'`) and the signature verifies over `UTF-8(canonical)`
   (`signature INVALID`, also when the signature is not base64url).
6. `canonical` parses as JSON (`canonical is not valid JSON`) and as an object (`canonical is <kind>, not a JSON
   object`). Its `schema`, `id`, `tenant_id`, `seq` and `prev_hash` must equal `pg.evidence.v1`, the envelope's `id`,
   the manifest's `tenant`, the envelope's `seq` and the envelope's `prev_hash`
   (`signed body <field>=<value> != <expected>`), compared as in section 7.1. Its `created_at` must be a string
   that parses as a time with a zone (section 9.2); else `signed created_at <value> is not an RFC 3339 time with a
   time zone`, the value in `repr` form.
7. Payment records: if the body's `decision_type` is `agent_spend` and `payload.event` is `payment.sign`, the checks
   of section 7.5.
8. Then `prev = body_sha256`, the envelope value, **even if step 3 or 5 failed**; and `expected_seq = seq + 1`,
   using the record's own seq, even if step 2 failed.

So the next record's link is checked against the envelope's `body_sha256` as written. A record whose hash or
signature fails is still a link in this sense: it is reported once, and the record after it is not reported as
broken because of it. A line left out in step 7.3.10 is not a link: the next record is compared with the last record
that was kept.

### 7.5 Payment records

Version 1 has **no sample record and no test vector** for payment records. The checks below describe the reference
verifier; nothing in the sample exercises them. The payload format is **not specified** (section 4.2).

For a `payment.sign` record, with `p` = `payload` and `a` = `p.authorization`:

1. **Authorization hash.** `p.authorization_sha256` must equal the hex SHA-256 of the UTF-8 bytes of the JSON object
   `{"amount":..,"asset":..,"network":..,"nonce":..,"pay_to":..,"payer":..,"valid_after":..,"valid_before":..}`,
   with keys sorted as shown, no whitespace, non-ASCII characters escaped as `\uXXXX`, and these string values:
   - `network`: `p.network` as written;
   - `asset`: the part of `p.asset_id` after `/erc20:`, lower-cased;
   - `payer`: `a.from`, lower-cased; `pay_to`: `a.to`, lower-cased; `nonce`: `a.nonce`, lower-cased;
   - `amount`: `a.value`; `valid_after`: `a.valid_after`; `valid_before`: `a.valid_before`, each converted to a
     string with Python's `str()`.

   Failure: `payment authorization_sha256 <value> does not recompute (<hex>)`.
2. **Same payer.** `a.from`, `p.payer` and `p.signer.payer` are equal ignoring case
   (`payment payer, authorization.from and signer.payer differ`).
3. **Value and recipient.** `a.value` equals `p.amount_units` exactly, type included; and `a.to` equals, ignoring
   case, the part of `p.pay_to` after its last `:` (`p.pay_to` is CAIP-10, `eip155:<chain>:<address>`)
   (`payment authorization value/to differ from amount_units/pay_to`).
4. **EIP-712 digest.** `p.eip712.digest` must equal, as a string, `0x` followed by the lowercase hex of
   (`payment eip712.digest <value> does not recompute (<hex>)`):

   ```
   domainSeparator = keccak256( keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                                || keccak256(UTF-8(domain.name)) || keccak256(UTF-8(domain.version))
                                || uint256(domain.chain_id) || address(domain.verifying_contract) )
   structHash = keccak256( keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
                           || address(a.from) || address(a.to) || uint256(a.value)
                           || uint256(a.valid_after) || uint256(a.valid_before) || bytes32(a.nonce) )
   digest = keccak256( 0x19 || 0x01 || domainSeparator || structHash )
   ```

   with `domain = p.eip712.domain`. A verifier needs **Keccak-256**: the original Keccak with padding byte `0x01`, as
   Ethereum uses, **not** FIPS 202 SHA3-256. `uint256(v)` is the 32-byte big-endian form of the integer `v`.
   `address(v)` is 12 zero bytes followed by the 20 bytes of `v`, a hex string with or without `0x`. `bytes32(v)` is
   the 32 bytes of `v`, a hex string with or without `0x`.

**Types.** EIP-3009 and x402 write `value`, `valid_after`, `valid_before` and `chain_id` as strings of decimal
digits, and addresses and the nonce as `0x`-prefixed hex strings. Other forms are **not specified**. The reference
verifier converts these four numbers with Python's `int()` for the digest (which accepts integers, decimal strings
and booleans, and truncates floats), and uses `str()` of the value for the hash (so the integer `5` and the string
`"5"` hash alike, but `5.0` does not). A missing member, a non-object where an object is expected, an `asset_id`
without `/erc20:`, an address that is not 20 bytes or a nonce that is not 32 bytes gives
`payment.sign record is missing a signed field (<why>)`. All payment messages start with `seq <n> (id <id>): `.

### 7.6 Anchors

This section runs only with `--tsa-roots` and when `anchoring.present` is true. It runs even when sections 7.3 to 7.5
found failures (once step 7.3.7 has passed). Without `--tsa-roots`, the verifier prints `ANCHORS NOT CHECKED`
(section 8) instead.

Let `first` and `last` be `seq_range` (undefined for an empty pack), `head` be `chain_head.seq`, and `tenant` the
manifest's tenant.

1. **Parse.** Read `anchors/statements.jsonl` and `anchors/proofs.jsonl` as JSON Lines, skipping lines that are
   empty or whitespace. A missing file counts as empty. A line that is not JSON or not an object gives
   `anchors/<file> line <n>: <why>` (n numbered in the file), and **no further anchor check runs**.
2. **Line shapes.** A statement line with a field of the wrong type (section 6.2, line fields) gives
   `anchors/statements.jsonl line <i>: <field> is <kind>, expected <wanted>` and is left out. A proof line with a
   field of the wrong type, or whose `path` holds a non-string, gives `anchors/proofs.jsonl line <i>: ...` and is
   left out. Here `<i>` counts the non-blank lines, not the lines of the file. Proofs are keyed by `anchor_seq`.
   Two proofs for the same anchor: the verifier keeps the first one, and the pack breaks invariant 4 (section 7.8).
3. No statement left: `manifest says anchors are present, but anchors/statements.jsonl holds no statement`. No
   further anchor check runs.
4. Each `anchors/tsa-certs/` file must be a DER certificate (`<path>: not a DER certificate`); one that is not is
   left out of the candidates.
5. **Statements**, in file order. For a line with `anchor_seq` n (messages start with `anchor <n>: `, except the
   link messages):
   1. `hex(SHA-256(UTF-8(statement))) == statement_sha256` (`statement_sha256 does not match the statement`).
   2. The statement parses as JSON (`statement is not JSON`) with the types of section 6.2
      (`malformed statement (<problems>)`). If not, the line is dropped, and the next statement line is treated as the
      first one (its link is not checked).
   3. `schema` is `pg.anchor.v1` and the statement's `anchor_seq` equals n (`not a pg.anchor.v1 statement for anchor
      <n>`).
   4. The statement's own `kid` equals the line's `kid` (`the statement names kid <kid>, the line that carries it kid
      <kid>`, both in `repr` form).
   5. The signature verifies under the line's `kid` (`statement signature INVALID (kid <kid>)`).
   6. The link. If an earlier statement line was kept, n must be its `anchor_seq` + 1
      (`anchor chain broken: anchor <n> follows anchor <m> (anchors missing)`); if it is, `prev_statement_sha256` must
      equal that line's `statement_sha256` (`anchor chain broken: anchor <n> does not name anchor <m>'s statement`).
      If this is the first kept line and n is 1, `prev_statement_sha256` must be 64 zeros
      (`anchor 1: prev_statement_sha256 is not the genesis value`). If n is not 1, the first link is not checked
      (section 2).
   7. `created_at` parses as a time with a zone (`bad created_at`).
   8. **Tokens.** Every element of `anchoring.tokens` whose `anchor_seq` is n, in manifest order, is checked (section
      6.5) on the pack file its `file` names. The valid token with the earliest `genTime` (the first, on a tie) gives
      the anchor's **time**. No valid token: `no valid TSA token (<tsa>: <why>; ...)`, or `(none in the pack)` when no
      element names n. **Not specified:** a `file` that is missing from the pack or not under `anchors/`; the reference
      verifier looks the path up among the files it read (the four required files and the `anchors/` files) and treats
      a missing one as empty bytes, which fails as a token. A `.tsr` file that no element names is not used (it must
      still be listed in `files`, step 7.3.13).
   9. A failure in 1, 3, 4, 5, 6, 7 or 8 marks anchor n as **not valid**. The anchor is kept for the next steps.
      **Not specified:** two statement lines with the same `anchor_seq`; the reference verifier reports a broken link
      and keeps the later one.
6. A proof for an anchor without a kept statement:
   `anchors/proofs.jsonl has a proof for anchor <n>, whose statement is missing`.
7. `anchoring.first_anchor_seq` and `last_anchor_seq` must equal the `anchor_seq` of the first and last kept statement
   lines (`anchors/statements.jsonl does not hold the manifest's anchors <a>..<b>`).
8. **Coverage.** Set `covered = seq_range.first - 1`, or 0 for an empty pack. Then, for each kept anchor in increasing
   `anchor_seq`:
   1. **Time order.** If the anchor has a time: it must not be earlier than the time of the previous anchor, in
      `anchor_seq` order, that has a time, valid or not
      (`anchor <n>: genTime <t> is before the previous anchor's <t'> (time order)`); and it must not be more than 5
      minutes before its statement's `created_at`
      (`anchor <n>: timestamped at <t>, before its statement was made (<created_at>)`). Either failure marks the anchor
      not valid.
   2. **Proof.** If there is no proof for n: a failure if an earlier anchor had one
      (`anchor <n>: this tenant's leaf is missing (it was in earlier anchors)`). Go to the next anchor.
   3. Parse `leaf_data` as an object with an integer `seq` (call it h) and a string `head_hash`; decode the path from
      hex and `merkle_root` from hex. Otherwise `anchor <n>: malformed proof`; next anchor.
   4. Let `from = covered + 1`, and `to = h` if `h >= from`, else `to = from`.
   5. The leaf's `tenant_sha256` must be the hex SHA-256 of `pg.anchor.tenant.v1:` + tenant, and its `v` must equal 1
      (`anchor <n>: the leaf is not this tenant's (another tenant's proof?)`; range from..to). Next anchor.
   6. The proof's `tree_size` must equal the statement's, and the inclusion proof (section 6.4) of
      `SHA-256(0x00 || UTF-8(leaf_data))` at `leaf_index` must reach `merkle_root`
      (`anchor <n>: the inclusion proof does not reach the anchored merkle_root`; range from..to). Next anchor.
   7. If the anchor is not valid: `anchor <n> does not verify, so it covers nothing (see above)` (range from..to if
      `h >= from`, else no seq). Next anchor.
   8. If h is lower than the highest h of the earlier anchors that reached this step:
      `anchor <n> saw head seq <h>, an earlier anchor saw <h'>: records removed` (seq h + 1). Checking continues.
   9. If h > `head`: `anchor <n> at <time> covers seq <h>, but the chain ends at seq <head>: records deleted`
      (seq head + 1). Next anchor.
   10. **Beyond the pack.** If the pack has records and h > `last` (possible when `chain_head.seq` is above `last`):
       the anchor saw a head that the pack does not hold, so nothing in the pack binds the records it would cover. It
       covers nothing, does not become the last valid anchor, and gives no failure; it is printed as
       `ANCHOR BEYOND THIS PACK` (section 8). Next anchor.
   11. If `first <= h <= last`: the record with seq h must exist and its `body_sha256` must equal `head_hash`
       (`seq <h> does not match the head anchored at <time> by <tsa> (anchor <n>): records <from>..<h> changed after
       they were anchored; --previous-pack names the exact one`; range from..h). Next anchor.
   12. **Backdating.** The first record, in file order, with seq above h whose body `created_at` is more than 5
       minutes before the anchor's time gives `recorded at <t>, before anchor <n> (<time>) saw the chain end at seq
       <h>: backdated` (that record's seq). A record whose `created_at` does not parse as a time with a zone is skipped
       here; it has already failed in step 7.4.6. Checking continues. Only anchors that reach this step take part, so
       only valid anchors with a matching proof.
   13. The anchor becomes the **last valid anchor**. So the last valid anchor verifies (step 5), passed the time
       order, has a proof for this tenant that reaches its `merkle_root`, and its head h either matches the pack's
       record at seq h or precedes the pack's first seq (h < `first`). An anchor without a checked proof never becomes
       the last valid anchor. In an empty pack, an anchor that reaches this step becomes the last valid anchor.
   14. If `h > covered` and `h >= first`: records `max(first, covered + 1)` to h are covered by this anchor (one
       coverage line, section 8), and `covered = h`.

   A failure at steps 5, 6, 7, 9 or 11 does not stop coverage: a later anchor that passes still covers from
   `covered + 1`. The pack still fails.
9. Records after the last covered seq are not covered: one `ANCHOR BEYOND THIS PACK` line for the first anchor, in
   `anchor_seq` order, that step 8.10 set aside, then one `NOT YET ANCHORED` line (section 8). An empty pack prints
   no coverage line, but its anchors are still checked by steps 1 to 8.

### 7.7 Options

- **`--require-anchors --anchored-since DATE` (audit mode).** These options and `--tsa-roots` need `--input`; else
  `FAIL: --tsa-roots / --require-anchors / --previous-pack need --input <pack>` and exit 2. `--anchored-since` without
  `--require-anchors` is a usage error: `FAIL: --anchored-since only applies with --require-anchors (pass both, or
  neither)`, exit 2. `--require-anchors` needs `--tsa-roots` and `--anchored-since`; else `FAIL: --require-anchors
  needs --tsa-roots and --anchored-since`, exit 2. DATE must parse as a time with a zone (section 9.2), else exit 2
  (for example `FAIL: '<DATE>' has no time zone`). DATE is when the signer started anchoring. It must come from the
  organisation that runs the signer, through a separate channel, never from the pack.

  Let `covered` be the last seq of the last coverage range (`ANCHORED` or `ANCHOR CHECKED, RECORDS FAILED`), or 0 if
  there is none; `interval` = `--anchor-interval` (default `10m`); `grace` = `--anchor-grace` (default `15m`). A
  duration is digits followed by `s`, `m` or `h`. Let **T** be the time of the last valid anchor (step 7.6.8.13) when
  there is one and it is later than DATE; otherwise T = DATE. T comes from a TSA token or from the user, never from
  the manifest or the records. Leaving out anchors, proofs or tokens, or keeping an anchor whose head lies beyond the
  pack, can only move T earlier. Let `limit = T + interval + grace`.

  Then, for each record in file order, with `latest` the earlier record with the latest `created_at` so far (the
  first one, on a tie):
  1. If its `created_at` does not parse: if its seq is above `covered`, the failure is `seq <n> is not covered by any
     anchor and its signed created_at is unreadable, so it cannot be shown to predate --anchored-since` (seq n), and
     checking stops. Otherwise the next record follows. (Such a record has already failed in step 7.4.6.)
  2. **Order.** If its time is more than 5 minutes before the time of `latest`: `seq <n>: signed created_at <t> is
     before seq <p>'s <t'>: records re-dated out of order` (seq n, p the seq of `latest`), and checking stops. This
     applies to every record, covered or not, before DATE or not. So no record may be dated more than 5 minutes before
     any earlier record, and records cannot creep back a few minutes at a time.
  3. If its seq is at most `covered`, or its time is before DATE, the next record follows.
  4. The first record that gets here is the **first uncovered** record F.
  5. **Grace rule.** If its time is at or after `limit`, checking stops with one failure that names seq F. When the
     record is F itself: `seq <F> (recorded at <tF>) and the records after it are not covered by any anchor: <rule>`.
     Otherwise: `seq <F> (recorded at <tF>) and the records after it are not covered by any anchor, but seq <n> was
     recorded at <t>: <rule>`. Here `<rule>` is `only records recorded before <limit> (<base> at <T> + interval
     <interval> + grace <grace>) may wait for the next anchor; anchoring runs since <DATE>`.

  So the pack fails when any record whose `created_at` is at or after DATE is not covered, unless every such record
  was recorded before `limit`. There is at most one audit failure. `<base>` is `the latest valid anchor <n>` when T is
  that anchor's time; otherwise `--anchored-since (the pack: it carries no anchors)` (`anchoring.present` is not
  true), `--anchored-since (the pack: none of its anchors verifies with a checked proof for this tenant)`, or
  `--anchored-since (the pack's latest valid anchor is older)`. Durations print as whole minutes (`10m`) when they are
  a non-zero multiple of 60 seconds, else as seconds (`90s`). An unexpected error in this step gives
  `--require-anchors: <why>`.

  **Honest packs that fail audit mode until exported again.** Nothing is wrong with the evidence in these cases;
  a pack exported later passes:
  - A pack of a tenant whose first records came after the latest anchor. The pack carries that anchor without a
    proof (the exception to invariant 5), so T is DATE. It fails until the next anchor includes the tenant, within
    the anchoring interval.
  - A pack exported right after a record that ended a quiet period. During a quiet period the signer anchors less
    often, so T can be up to an hour old (depending on the signer's configuration), and the new record is past
    T + 25 minutes until the next anchor, within the interval.
  - A pack that hit the signer's record limit, so its range could not reach the head of the anchor that covers its
    last record. That anchor lies beyond the pack (step 7.6.8.10); the tail is uncovered and T comes from the anchor
    before it, or is DATE. Export a narrower window.
- **`--previous-pack OLD`** (needs `--input`): OLD is checked by sections 7.2 to 7.5 with the same pin, not its
  anchors. If it fails: `--previous-pack <OLD> does not verify: <its first failure>`. It must be for the same tenant
  (`--previous-pack is for tenant '<a>', not '<b>'`). Then, for the records of OLD in order: the first one whose seq is
  also in the pack with a different `body_sha256` gives `differs from the previous pack (<file name>): record <id>
  there, <id> here` (its seq); the first one whose seq is not in the pack and is above `chain_head.seq` gives `the
  previous pack holds seq <s>, the chain now ends at seq <head>: records deleted` (seq head + 1). Checking stops at
  the first of these. Otherwise a `PREVIOUS PACK` line is printed.
- **`--match-payment VALUE`** (`@FILE` reads it from a file, `-` from standard input): VALUE is the base64 (standard
  or base64url alphabet) x402 v2 `PaymentPayload` of a `PAYMENT-SIGNATURE` header (exact scheme, EVM). After the pack
  verifies, the verifier computes the authorization hash of section 7.5 from the payload's `accepted.network`
  (lower-cased if it starts with `eip155:`), `accepted.asset` and `payload.authorization`, and finds the first
  `payment.sign` record with that `authorization_sha256`. It recomputes the EIP-712 digest from that record's domain
  and the payload's authorization, recovers the secp256k1 public key from the payload's 65-byte signature (`r || s ||
  v`, v in {0, 1, 27, 28}), checks the signature under it, and compares its Ethereum address with the record's
  `payer`. Not exercised by the sample (section 10).

### 7.8 Pack invariants

The signer builds the anchor part of every pack the same way. The verifier checks that structure, with or without
`--tsa-roots`, whenever the manifest passed step 7.3.7. The checks are structural: no signature and no token is
checked here. Each broken invariant gives one message, listed below.

- **In audit mode** (`--require-anchors`) each is a failure: `pack invariant broken: <why>`. Only the message of the
  exception in invariant 5 names a seq; the others name none.
- **Otherwise** each prints `WARNING: pack invariant broken: <why> (a pack exported by PolicyGate never looks like
  this; --require-anchors fails on it)` on standard output, and the exit code does not change. With
  `--match-payment`, the warnings are not printed.

An unexpected error gives one message: `cannot check (<why>)`. Below, "anchor files" are the paths under `anchors/`
in the pack or in the manifest's `files`, in sorted order.

1. If `anchoring.present` is not true, there are no anchor files: `the manifest says the pack carries no anchors, yet
   it holds or declares <up to three names>` (`, ...` when there are more). Nothing else is checked.
2. If `anchoring.present` is true, the pack has records (`anchors in a pack with no records (an empty window carries
   none)`; nothing else is checked), and holds `anchors/statements.jsonl` and `anchors/proofs.jsonl` (`<file> is
   missing (every anchored pack carries it)`). If either file is not valid JSON Lines, nothing else is checked here
   (section 7.6 reports it). No statement at all: `anchors/statements.jsonl holds no statement`, and nothing else is
   checked.
3. **Statements.** Their `anchor_seq` values are integers and exactly `first_anchor_seq`..`last_anchor_seq`, in
   order, one each (`anchors/statements.jsonl holds anchors <list>, not <a>..<b> in order, one each`). Their number
   equals `anchoring.anchors` (`anchors/statements.jsonl holds <k> statement(s), the manifest says <v>`).
4. **Proofs.** `anchoring.tenant_sha256` is this tenant's hash (`the manifest's anchoring.tenant_sha256 is not this
   tenant's`). At most one proof per anchor (`anchors/proofs.jsonl holds <k> proofs for anchor <n> (one per
   anchor)`), in anchor order (`anchors/proofs.jsonl is not in anchor order`), each for a statement in the pack
   (`anchors/proofs.jsonl holds a proof for anchor <n>, which has no statement in the pack`). Their number equals
   `anchoring.proofs` (`anchors/proofs.jsonl holds <k> proof(s), the manifest says <v>`). Each holds this tenant's
   leaf (`the proof for anchor <n> holds another tenant's leaf`), for a tree of the statement's `tree_size` (`the
   proof for anchor <n> is for a tree of <x> leaves, its statement says <y>`).
5. **Every statement has a proof for this tenant.** With more than one statement: `anchor(s) <list> have no proof for
   this tenant: a pack with more than one anchor holds a proof for each (every anchor after a tenant's first record
   holds its leaf)`.

   **The one legitimate exception:** a pack that no anchor covers carries just the latest anchor, and has no proof
   for it when the tenant had no records yet when that anchor was made. So a pack with exactly one statement may lack
   its proof, but then no record may be dated more than 5 minutes before the statement's `created_at`. The first
   record, in file order, that is gives `the pack has no proof for this tenant under its only anchor <n>, which a
   PolicyGate pack has only when the tenant had no records yet when that anchor was made (<time>), but seq <s> was
   recorded at <t>` (seq s). Such an anchor never becomes the last valid anchor, so T is DATE in audit mode.
6. **Where a pack starts and ends.** With more than one statement, the heads below come from the proofs. The first
   statement's head is at or after the pack's first seq (`the pack's first anchor <n> saw seq <h>, before the pack's
   first seq <first>: a pack with more than one anchor starts at the first anchor that covers its first record`).
   Every statement but the last has a head before the pack's last seq (`anchor <n> already covers the pack's last seq
   <last>, yet later anchors follow: a pack ends at the first anchor that covers its last record`; the first such
   anchor only).
7. **Tokens.** For each element of `anchoring.tokens`:
   - it names an anchor with a statement in the pack (`a token entry names anchor <n>, which has no statement in the
     pack`);
   - its `file` is exactly `anchors/tokens/<anchor_seq>-<tsa>.tsr`, where `<tsa>` is the element's `tsa` and matches
     `[A-Za-z0-9._-]+` (`the token entry for anchor <n> by <tsa> points at <file>, not anchors/tokens/<n>-<tsa>.tsr`);
     if it is, the file is in the pack (`<file> (the token of anchor <n>) is missing from the pack`);
   - no two elements name the same file (`two token entries point at <file>`).

   The elements are in anchor order (`the manifest's token entries are not in anchor order`). Every statement has at
   least one element (`anchor(s) <list> have no TSA token entry (every anchor is stored only once a TSA answered)`).
   Every anchor file under `anchors/tokens/` is named by an element (`<file> is not named by any token entry`).
8. **Certificates.** Every anchor file under `anchors/tsa-certs/` is named `<hex SHA-256 of its bytes>.der`
   (`<file> is not named after its SHA-256`). Together they are exactly the manifest's `anchoring.tsa_certs` (`the
   anchors/tsa-certs/ files are not the manifest's tsa_certs`).
9. **No other anchor file** (`<file> is not a file an anchored pack carries`).

## 8. Output and exit codes

Standard output, in this order:

| Line | When |
|---|---|
| `ANCHORED: seq <a>..<b> covered by <root name> (<signer CN>) at <time> (anchor <n>)` | per covered range, with `--tsa-roots`, when no record in it failed |
| `ANCHOR CHECKED, RECORDS FAILED: seq <a>..<b>: anchor <n> (<root name> (<signer CN>) at <time>) verifies, but seq <x> in this range failed its own checks (see the FAIL lines), so the range is not proven` | instead of `ANCHORED`, when the range holds a failed record |
| `ANCHOR BEYOND THIS PACK: anchor <n> saw seq <h>, after this pack's last seq <last>, so it proves nothing about seq <c>..<last> here (export a pack that reaches seq <h> to check them)` | with `--tsa-roots`, when records after the covered range remain and an anchor's head lies beyond the pack (step 7.6.8.10); the first such anchor only |
| `NOT YET ANCHORED: seq <c>..<d> (after <time of the last valid anchor>)` | records after the covered range, with `--tsa-roots`, when a last valid anchor exists (step 7.6.8.13) |
| `NOT YET ANCHORED: seq <c>..<d> (no anchor in this pack verifies with a checked proof for this tenant)` | the same, when there is no last valid anchor |
| `WARNING: pack invariant broken: <why> (a pack exported by PolicyGate never looks like this; --require-anchors fails on it)` | per broken invariant, without `--require-anchors` (section 7.8) |
| `ANCHORS NOT CHECKED: this pack carries anchors <first>..<last>; pass --tsa-roots <your pinned roots> to check them` | anchored pack without `--tsa-roots` |
| `NOT ANCHORED: this pack carries no anchors` | `anchoring.present` not true and `seq_range` not null |
| `PREVIOUS PACK: the <k> record(s) both packs hold are identical` | with `--previous-pack`, when equal |
| `OK: pack=<input> tenant=<tenant> records=<record_count> seq=<first>..<last> anchor=<start hash> head_seq=<chain_head.seq> export_id=<export_id>` | the pack verified |
| `KEY NOT PINNED: verified against the key inside this pack (kid <kid>). Compare it with the signer's published key, or pass --expect-kid.` | no `--expect-kid` and no `--keys-file` |

In the `OK` line, `<input>` is the `--input` value as given; `anchor=` shows the start hash; for an empty pack,
`seq=none (empty window)`; a null start hash or `chain_head`, or a missing `export_id`, prints as `None`. With several
kids, the last line reads `the keys inside this pack (kids <k1>, <k2>)`, the manifest's kid first, then those of
records and statement lines in order of first use. Times are UTC, `YYYY-MM-DDTHH:MM:SSZ` (seconds, truncated).

The coverage lines are printed **before** any failure, and also when the pack fails. A range is printed as `ANCHOR
CHECKED, RECORDS FAILED` when a failure from sections 7.3 to 7.5 names a seq inside it (rule below). `<x>` lists those
seqs in increasing order, separated by `, `: at most five, then `, ...`. The anchor fixes the chain of `body_sha256`
values, so it can verify while a record's contents fail; such a range is not proven. The failures and the exit code
decide.

With `--match-payment`, instead of the `OK` line: `MATCH: record <id> seq <n> tenant=... agent=... payment_id=...
amount_units=... asset=... pay_to=... payer=... authorization_sha256=... decided_at=...`, followed by the anchor
status of that record (`ANCHORED: seq <n> covered by ...`, `NOT YET ANCHORED: seq <n> (...)`, `NOT ANCHORED: seq <n>
(this pack carries no anchors)`, or `ANCHOR STATUS: not checked (pass --tsa-roots)`); or `NO MATCH: <why>. No policy
decision in this pack (tenant=<t>, <from>..<to>) covers this payment.`

**Standard error, on failure:**

1. `FAIL: first bad seq <n> (<message>)`, when at least one failure names a seq (rule below).
2. `FAIL: <message>` for every failure, in the order found: sections 7.3 to 7.5, then the pack invariants (section
   7.8, audit mode only), then the anchors (7.6), then `--require-anchors` and `--previous-pack` (7.7).
3. `FAIL: <k> problem(s) in <input>`.

**Which failures name a seq.** A failure names either one seq (exact) or a range `from..to`.

- Exact, from sections 7.3 to 7.5: a message that contains `expected seq <m>` names m (so a gap names the missing
  seq); any other message that starts with `seq <n>` names n. This covers the record checks and the `chain_head`
  check.
- Exact, from sections 7.6 to 7.8: `records removed` (h + 1), `records deleted` (head + 1), `backdated` (the record's
  seq), the `--require-anchors` and `--previous-pack` failures (the seq given in 7.7), and the exception message of
  invariant 5 (section 7.8).
- Range: the four anchor failures marked "range" in step 7.6.8 (the leaf is not this tenant's; the inclusion proof;
  the anchor does not verify; the head does not match), with `from` and `to` as computed there.
- All other failures name no seq.

**Which one is printed first.** Let E be the exact failure with the lowest seq (the first such, on a tie), and R the
range failure with the lowest `to` (then the lowest `from`). If E exists, and either R does not exist or E's seq is
`<= R.to`, print E's seq and message. Otherwise print R's `from` and R's message.

Usage errors print one `FAIL: <why>` line. Input that escapes every check ends in
`FAIL: malformed pack (<error type>: <message>)`, never a traceback.

| Exit code | Meaning |
|---|---|
| 0 | the pack verified (and, with `--match-payment`, MATCH) |
| 1 | verification failed, or NO MATCH |
| 2 | usage error: bad options, a bad `--expect-kid`, `--keys-file` or `--tsa-roots` file, a bad date or duration, an unreadable or undecodable `--match-payment` value |

## 9. Other details

### 9.1 Input limits

A pack is untrusted input. All limits below are strict: a value equal to the limit passes.

**Zip.** Before reading any entry, the verifier rejects (`REJECTED: <why>`): more than 50 000 entries; two entries with
the same name; a name that is empty, starts with `/`, starts with a drive letter (`C:`), contains a backslash or a NUL,
or has `..` or an empty part between `/`; a symlink entry; an entry of more than 1 GiB; more than 2 GiB in all; and
an entry of more than 1 MiB whose size is more than 200 times its compressed size (its compressed size taken as at
least 1). Sizes are those the zip's central directory declares.

**Directory.** For the four required files and every file under `anchors/`: each must be a regular file, not a
symlink, of at most 1 GiB; `anchors/` and the directories below it must not be symlinks; at most 50 000 files are
read; the files read must total at most 2 GiB (checked after reading). There is no name check and no ratio check.
Other files in the directory are not read. A failure gives `REJECTED: <why>`.

**JSON.** `manifest.json`: at most 32 MiB. Each line of `records.jsonl`, `anchors/statements.jsonl` and
`anchors/proofs.jsonl`; each `canonical`, `statement` and `leaf_data`; `jwks.json`; a `--keys-file` and a
`--tsa-roots` file: at most 1 MiB. Any JSON text: objects and arrays nested at most 64 deep (counted outside
strings). Over a JSON limit, the step that reads the text fails with its own message (for example
`manifest.json: not valid JSON (manifest.json: <n> bytes, more than the limit <limit>)`).

### 9.2 Times the verifier reads

The verifier parses times only in these places: a statement's `created_at` (step 7.6.5.7 and invariant 5), a record
body's `created_at` (step 7.4.6, backdating, invariant 5 and `--require-anchors`) and `--anchored-since`. It does not
parse the manifest's `created_at`. It strips surrounding whitespace, replaces a final `Z` with `+00:00` and uses
Python's `datetime.fromisoformat`, which accepts more than RFC 3339 (for example a space instead of `T`). A time
without a zone is an error. The formats in section 1 are what the signer writes; the verifier does not check them,
and does not parse `decided_at`, `recorded_at` or `window`.

### 9.3 Online mode

`--base-url URL --tenant T` reads the deployment's keys from `GET /v1/evidence/keys` (no credential) and the chain from
`GET /v1/evidence/chain?tenant=T&fromSeq=N&limit=500` (pages of 500, `Authorization: Bearer <token>` from `--token` or
`POLICYGATE_EVIDENCE_READ_TOKEN`; the response is `{"records": [...]}` with the record lines of section 4.1). It runs
the chain check of section 7.4 from `--from-seq` (default 1), with the previous hash 64 zeros at seq 1, else
`--expect-prev-hash`, else none. A record that is not a valid record line gives `record <i> (expected seq <n>): not a
valid record (<why>)`. It prints `OK: tenant=<t> records=<n> seq=<a>..<b> head=<hash> anchor=<genesis |
--expect-prev-hash | UNANCHORED>`. In this line, `anchor=` names what the first `prev_hash` was checked against
(`UNANCHORED`: nothing); it has nothing to do with anchors. This mode uses the network and is not needed to verify a
pack.

## 10. What verification proves and what it does not

The **full audit command** is `verify-evidence.py --input PACK --expect-kid KID --tsa-roots ROOTS --require-anchors
--anchored-since DATE`, with KID, ROOTS and DATE obtained by the auditor, not taken from the pack. When it exits 0, it
shows:

- The manifest, every record and every anchor statement line in the pack were signed by the key with id KID, and
  every statement names KID itself.
- Every record is unchanged since it was signed: its body hashes to `body_sha256` and its signature holds.
- The records form one unbroken chain from `seq_range.first` to `seq_range.last`, with no gap, no reordering, and no
  record removed from the middle or the end of the range the manifest names.
- The files `records.jsonl`, `jwks.json` and every `anchors/` file are the ones the signed manifest names.
- For each `ANCHORED: seq a..b` line: a TSA whose root you pinned signed, at the time shown, a statement that fixes
  the tenant's chain of record hashes up to seq b, and every record in a..b passed its own checks. So records a..b in
  the pack are the ones that existed then.
- Every record whose signed `created_at` is at or after DATE is covered by an anchor, except records recorded before
  T + interval + grace (section 7.7), where T is the time of the latest anchor whose proof for this tenant was
  checked. No record's `created_at` is more than 5 minutes before that of any earlier record.
- The pack's anchor part has the structure the signer always gives it (section 7.8).

**What a key holder can still do under the full audit command.** Whoever holds the private key for KID (the
organisation that runs the signer, or anyone who has taken the key) can still do the following. None of it can be
closed from inside one pack, because the only times in a pack that the key holder does not choose are the TSA times
of the anchors it keeps.

- Rewrite, re-date, add or drop the newest records, those recorded after the latest anchor the pack keeps. The grace
  rule bounds when: all of them must claim times before T + interval + grace (25 minutes by default) and, in order,
  no earlier than 5 minutes before any earlier record.
- Present the pack as if it was exported earlier: keep the anchors up to some anchor k, with their statements,
  proofs and tokens, drop every later anchor, and drop or rewrite the records after anchor k's head, all dated
  before anchor k's time + 25 minutes. Records that the dropped anchors covered can be changed this way; a pack that
  really was exported then looks the same. The same holds for a pack that ends before the head of its last anchor:
  that anchor then covers nothing in it (`ANCHOR BEYOND THIS PACK`). The anchors kept still fix everything they
  cover.
- Leave out all anchors and date every record of the pack before DATE, in order. The pack then claims to predate
  anchoring and prints `NOT ANCHORED`. Compare the records' times with the window you asked for.
- Make a pack of a different, shorter window, or of another tenant. The verifier checks what a pack holds, not that
  it is the pack you asked for. Compare the tenant, window and seq range with your request, and use `--previous-pack`
  to tie consecutive packs together.
- Change the `verify-evidence.py` and `README.txt` inside the pack, which no signature covers.

**What a key holder can no longer do under the full audit command:**

- Change, remove, insert or reorder any record that an anchor in the pack covers: the head hash the TSA dated binds
  the chain up to it.
- Make the grace rule start later than the latest anchor whose proof was checked. Leaving out proofs, statements,
  tokens or whole anchors, or keeping an anchor whose head lies beyond the pack, only moves T earlier.
- Keep real statements and tokens without their proofs, keep proofs or tokens without their statements, duplicate,
  reorder or swap proofs and tokens, point a token entry at another file, or leave anchor files empty or undeclared:
  each is a failure, from an anchor check or a pack invariant.
- Use another tenant's real proof, or a proof that does not reach the anchored `merkle_root`.
- Stretch the grace period with the manifest's `created_at` or anything else in the pack: interval and grace are the
  auditor's options.
- Re-date uncovered records to before DATE, or let them creep back a few minutes per record, while any earlier
  record is at or after DATE; or date a record above an anchor's head more than 5 minutes before that anchor's time
  (backdating, step 7.6.8.12).
- Make an anchor: every anchor needs a token from a TSA whose root the auditor pinned.
- Sign a statement that names another key: the statement's `kid` must equal its line's pinned kid.

Verification also does not show:

- **Who signed, without a pin.** Without `--expect-kid` or `--keys-file`, `ANCHORED` lines say nothing about who
  signed. The TSA token covers the statement text, not the key that signed the line. A forger can keep the
  timestamped statements and the records unchanged, re-sign every line, the statements and the manifest with their
  own key, and get the same `ANCHORED` lines and `OK`. Only the kid on the `KEY NOT PINNED` line differs.
- **That KID belongs to the organisation you think it does.** That depends on how you obtained KID. A key id printed
  next to the pack, by the same party, only shows that the two agree. The same holds for DATE.
- **Without `--require-anchors`, that anchors were not left out.** A pack without anchors exits 0 and prints
  `NOT ANCHORED`.
- **When a decision was made.** `decided_at` and `in_window` are not signed. Records are not checked against the
  signed `window` or `in_window_count`. The time checks rely on the signed body's `created_at`, which the signer
  writes.
- **That the TSA roots are the right ones.** The verifier trusts the roots it is given. The file `tsa-roots.json`
  published with the sample comes from the same party as the sample; check each root yourself (section 6.6). There is
  no revocation check and no nonce check. SHA-1 in ESS `signingCertificate` (version 1) is accepted, because the
  authorities' tokens use it; the sample's do.
- **That the pack holds every record of the tenant.** It holds a seq range; records outside it are not covered.
- **That every request was recorded.** A record exists only for decisions the signer made and recorded.
- **That a decision was correct**, or that a model's answer was right. A record shows what was decided, on what
  policy revision, and when.
- **Legal certification of time.** An RFC 3161 timestamp is a signed statement by a TSA, trusted as far as you trust
  that TSA's root.

**What the sample and the tests exercise.** The sample exercises one timestamp path: FreeTSA, ECDSA with SHA-512,
ESS `signingCertificate` version 1, the signer found by issuer and serial number, no certificates in the token (all
from `anchors/tsa-certs/`), a chain of two certificates, one token per anchor, and two anchors in a tree of 16
leaves. The unit tests that come with the reference verifier build packs with throwaway keys. They cover the record,
chain, manifest, pinning, zip-limit and malformed-input checks, the online mode against a local server, and audit
mode against packs forged with the signing key. The audit tests use a throwaway TSA: an Ed25519 signer, ESS
`signingCertificateV2`, the signer found by issuer and serial number, its certificate and root inside the token, one
token per anchor, the tenant's leaf at index 0 and another tenant's at index 1 of a tree of 16 leaves. They reach the
grace rule, the order rule, backdating, the statement kid check, an anchor that does not verify, another tenant's
proof, a missing leaf, a head mismatch, an anchor beyond the pack, the pack invariants (as failures and as warnings),
and the `ANCHOR CHECKED, RECORDS FAILED` line.
These paths are **not exercised** by the sample or the unit tests:

- RSA (PKCS#1 v1.5 or PSS) TSA signers; a signer found by subject key identifier; chains longer than two
  certificates; `grantedWithMods`; several tokens for one anchor; the Sectigo root in `tsa-roots.json`.
- The anchor failures for a bad inclusion proof, records removed and records deleted; time order between anchors.
- `--previous-pack` when both packs verify; payment records with valid values; `--match-payment`.
