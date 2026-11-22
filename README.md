# evidence-verifier

`verify-evidence.py` checks a PolicyGate evidence pack offline, from files only. You do not need access to
PolicyGate, and you do not need to trust it.

PolicyGate is self-hosted: it runs in the infrastructure of the organisation that uses it. It records each policy
decision as a signed, hash-chained record, and it can export the records of one tenant as an evidence pack (a zip
file). Anyone who receives a pack can check it with this script:

- every record is signed by the deployment's key and has not changed since;
- the records form one chain, with no gap, no reordering and nothing removed in the range the pack names;
- the pack's files are the ones its signed manifest names;
- with anchors: an outside time-stamp authority (RFC 3161) dated the chain, so records cannot be rewritten later
  without detection.

[SPEC.md](SPEC.md) describes the format and every check, precisely enough to write your own verifier.

## Requirements

- Python 3.11 or newer.
- The pinned dependencies in `requirements-verify.txt` (`cryptography`, and `asn1crypto` for anchors), installed with their
  hashes:

```
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r requirements-verify.txt
```

## Try it on the sample

`sample/example-bank.zip` is a real pack. `sample/example-bank/` holds the same files unpacked, so you can read the
records here. The commands below were run on this repository with networking disabled. The output is copied
unchanged.

### a) Verify the sample, with the key pinned and the time-stamp roots given

```
$ python3 verify-evidence.py --input sample/example-bank.zip \
    --expect-kid 0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk --tsa-roots tsa-roots.json
ANCHORED: seq 1..1 covered by freetsa (www.freetsa.org) at 2026-11-21T15:21:29Z (anchor 358)
ANCHORED: seq 2..7 covered by freetsa (www.freetsa.org) at 2026-11-21T15:31:30Z (anchor 359)
OK: pack=sample/example-bank.zip tenant=example-bank records=7 seq=1..7 anchor=0000000000000000000000000000000000000000000000000000000000000000 head_seq=7 export_id=1b8ec90a-c459-4f7d-b6e3-0b30ee2bb5bc
$ echo $?
0
```

All 7 records are covered by two timestamps from FreeTSA.

### b) Verify the tampered copy

`sample/example-bank-tampered.zip` is the same pack with one field changed: in record seq 3, the outcome `deny`
became `allow`, so the denied `gpt-4o` call looks allowed. Nothing was re-signed. [sample/TAMPERED.md](sample/TAMPERED.md)
shows the change.

```
$ python3 verify-evidence.py --input sample/example-bank-tampered.zip \
    --expect-kid 0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk --tsa-roots tsa-roots.json
ANCHORED: seq 1..1 covered by freetsa (www.freetsa.org) at 2026-11-21T15:21:29Z (anchor 358)
ANCHOR CHECKED, RECORDS FAILED: seq 2..7: anchor 359 (freetsa (www.freetsa.org) at 2026-11-21T15:31:30Z) verifies, but seq 3 in this range failed its own checks (see the FAIL lines), so the range is not proven
FAIL: first bad seq 3 (seq 3 (id 431f8ed7-887c-43d6-b546-cb04166ad39a): sha256(canonical)=a6fc3eed008f6b3f1fe5119842e568da5cd66d95e55a68815f5661b70ac2ef26 != body_sha256=da4e8a5544e99bff29aecd86be3694199e7378e07e8775b0dc1fa31dbf89c189)
FAIL: seq 3 (id 431f8ed7-887c-43d6-b546-cb04166ad39a): sha256(canonical)=a6fc3eed008f6b3f1fe5119842e568da5cd66d95e55a68815f5661b70ac2ef26 != body_sha256=da4e8a5544e99bff29aecd86be3694199e7378e07e8775b0dc1fa31dbf89c189
FAIL: seq 3 (id 431f8ed7-887c-43d6-b546-cb04166ad39a): signature INVALID
FAIL: records.jsonl: sha256 31575175bce3c9f19687114ddfa363bf3d702a723df69ba81cc77b293ee2606b does not match the manifest
FAIL: 3 problem(s) in sample/example-bank-tampered.zip
$ echo $?
1
```

The pack fails, and the first `FAIL` line names seq 3. Anchor 359 itself still verifies, because it fixes the chain
of record hashes (`body_sha256`) and the change did not touch those. But its range holds a record that failed its own
hash and signature check, so the range is reported as `ANCHOR CHECKED, RECORDS FAILED`, not as `ANCHORED`. The result
of the run is the exit code: 1.

### c) Verify the sample without pinning the key

```
$ python3 verify-evidence.py --input sample/example-bank.zip --tsa-roots tsa-roots.json
ANCHORED: seq 1..1 covered by freetsa (www.freetsa.org) at 2026-11-21T15:21:29Z (anchor 358)
ANCHORED: seq 2..7 covered by freetsa (www.freetsa.org) at 2026-11-21T15:31:30Z (anchor 359)
OK: pack=sample/example-bank.zip tenant=example-bank records=7 seq=1..7 anchor=0000000000000000000000000000000000000000000000000000000000000000 head_seq=7 export_id=1b8ec90a-c459-4f7d-b6e3-0b30ee2bb5bc
KEY NOT PINNED: verified against the key inside this pack (kid 0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk). Compare it with the signer's published key, or pass --expect-kid.
$ echo $?
0
```

### Why pinning matters

A pack carries its own public key (`jwks.json`). Without a pin, the script checks the pack against that key. Someone
who forges a whole pack with a new key of their own gets the same `OK`. The only difference is the key id on the
`KEY NOT PINNED` line.

`--expect-kid` tells the script which key to accept. Then a pack signed with any other key fails. `--keys-file`
does the same with a JWKS file.

Be clear about what the key id above shows. It is printed in the same repository as the pack, by the same party.
That only shows that the two agree. In a real audit, the auditor gets the key id from the organisation that runs
PolicyGate, through a separate channel, and does not take it from the pack or from the party that handed over the
pack.

The same applies to `tsa-roots.json`: it holds the root pins for the time-stamp authorities, with notes on where
each root came from. An auditor should get each root from the authority's own publication and compute the pin
themselves (SPEC.md, section 6.6).

## For a real audit

Pin the key, give your own time-stamp roots, and require anchors:

```
$ python3 verify-evidence.py --input sample/example-bank.zip \
    --expect-kid 0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk --tsa-roots tsa-roots.json \
    --require-anchors --anchored-since 2026-11-07T16:07:00Z
ANCHORED: seq 1..1 covered by freetsa (www.freetsa.org) at 2026-11-21T15:21:29Z (anchor 358)
ANCHORED: seq 2..7 covered by freetsa (www.freetsa.org) at 2026-11-21T15:31:30Z (anchor 359)
OK: pack=sample/example-bank.zip tenant=example-bank records=7 seq=1..7 anchor=0000000000000000000000000000000000000000000000000000000000000000 head_seq=7 export_id=1b8ec90a-c459-4f7d-b6e3-0b30ee2bb5bc
$ echo $?
0
```

`--anchored-since` is when the deployment started anchoring. The reference deployment that signed the sample made
its first anchor at 2026-11-07T16:07:00Z. That date and the key id are also published at
<https://policygate.ai/proof>. In a real audit, both come from the organisation that runs PolicyGate, through a
separate channel, never from the pack.

With `--require-anchors`, every record signed at or after that date must be covered by an anchor in the pack that
verifies and whose proof for this tenant checks out. Only the newest records may wait for the next anchor: those
signed less than 25 minutes (the anchoring interval plus a grace period) after the latest such anchor, or after
`--anchored-since` if the pack has none. No record may be dated more than 5 minutes before an earlier one, and the
pack's anchor files must have the structure PolicyGate always gives them (SPEC.md, section 7.8). Without
`--require-anchors`, a broken structure only prints a `WARNING` line. For this sample the
output is the same as in a), because every record is covered. SPEC.md, section 7.7, gives the exact rule.

## How the sample was made

- Tenant `example-bank` is synthetic. It was created on PolicyGate's own reference deployment for this repository.
  No real organisation and no real data are involved. The pack holds no prompts and no answers: a request's input
  appears only as a SHA-256 hash (`input_sha256`).
- The pack holds 7 records:
  - seq 1: creation of the tenant (`admin_change`);
  - seq 2, 4 and 7: allowed AI calls (`gpt-4o-mini`);
  - seq 3: denied, `model.not_allowed` (`gpt-4o`, a model the tenant may not use);
  - seq 5: denied, `authz.missing_scope`;
  - seq 6: denied, `residency.jwt_region_mismatch`.
- The caller's subject in the AI call records is `support-assistant`.
- The requests were sent from the deployment's own host. That is why the records show host `127.0.0.1:10000` and
  region `tst`.
- All 7 records are covered by two RFC 3161 timestamps from FreeTSA (anchors 358 and 359).
- Signing key id (kid): `0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk`.

## Limits

- Tamper-evident, not impossible to tamper with. Whoever holds the private signing key can sign a different chain.
  With a pin, a pack made with another key fails. With the full audit command, records that an anchor in the pack
  covers cannot be changed, removed or reordered without detection.
- A pack made with a forged key verifies unless the key is pinned. Without a pin, `ANCHORED` lines say nothing about
  who signed: a forger can keep the timestamped statements and re-sign everything with their own key.
- Without `--require-anchors`, a pack with its anchors left out still exits 0 and says `NOT ANCHORED`.
- Even with the full audit command, the key holder can still rewrite the records after the latest anchor the pack
  keeps, if they are dated within 25 minutes of it. By leaving out the latest anchors, or by ending the pack before
  the head of its last anchor (`ANCHOR BEYOND THIS PACK`), the key holder can make a pack look as if it was exported
  earlier. The key holder can also date every record before `--anchored-since` and leave out all anchors; the pack
  then says `NOT ANCHORED`. Compare the records' times and seq range with the window you asked for. SPEC.md,
  section 10, has the full list.
- Some honest packs fail the audit command until they are exported again, for example a pack exported right after a
  quiet period (SPEC.md, section 7.7).
- The script checks what a pack holds, not that it is the pack you asked for. Compare the tenant, window and seq
  range with your request.
- A timestamp is not legal certification. It is a signed statement by a time-stamp authority, trusted as far as you
  trust its root.
- A record shows what was decided, under which policy revision, and when. It does not show whether a model's answer
  was right.
- A pack holds one tenant's records for a time window. It says nothing about records outside that window.

SPEC.md, section 10, lists what a successful verification proves and what it does not.

## Verify a pack from your own PolicyGate

1. Get an evidence pack for a tenant and a time window from your PolicyGate deployment.
2. Get the deployment's signing key id through a channel you trust, separate from the pack: from the people who
   run the deployment, or from `GET /v1/evidence/keys` on the deployment, read on a connection you trust.
3. Get the roots of the time-stamp authorities your deployment uses, from the authorities themselves, and write
   your own `tsa-roots.json` (format in SPEC.md, section 6.6).
4. Ask the people who run the deployment when it started anchoring.
5. Run:

```
python3 verify-evidence.py --input evidence.zip --expect-kid <your kid> --tsa-roots <your tsa-roots.json> \
    --require-anchors --anchored-since <when your deployment started anchoring>
```

Exit code 0 means the pack verified. Any other exit code means it did not: read the `FAIL` lines. Use the
`verify-evidence.py` from this repository, not the copy inside the pack, which no signature covers.

`python3 verify-evidence.py --help` lists the other options: `--keys-file`, `--require-anchors`,
`--previous-pack` (compare with a pack you kept earlier) and `--match-payment`.

## Tests

```
python3 -m unittest discover -s tests -v
```

The tests build small packs with throwaway keys, and check the sample and the tampered copy. They need no network
other than the local loopback.

## More

- [SPEC.md](SPEC.md): the pack format and the verification steps.
- <https://policygate.ai/proof>: the published key id and first anchor date of the deployment that signed the sample.
- [SECURITY.md](SECURITY.md): how to report a security problem.

## License

Copyright 2026 PolicyGate.

The code is licensed under the Apache License 2.0 ([LICENSE](LICENSE)). The sample data in `sample/` is dedicated to
the public domain under CC0 1.0 ([sample/LICENSE](sample/LICENSE)). The copy of `verify-evidence.py` inside each
sample pack is the same code as `verify-evidence.py` and stays under the Apache License 2.0.
