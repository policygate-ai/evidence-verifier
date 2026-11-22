"""Builds small pg.evidence.export.v1 packs for tests, signed with throwaway Ed25519 keys (never a real signer's).

    signer = Signer()
    records = chain(signer, "demo", 3)                 # seq 1..3, linked, signed
    files = pack_files(records, signer, "demo")        # {name: bytes}: records.jsonl, jwks.json, manifest.*
    write_zip(path, files)  /  write_dir(path, files)

Tamper helpers re-sign what a forger with the key would re-sign: resign(record, signer) recomputes body_sha256 and
the signature of one record; pack_files(..., edit=lambda m: ...) edits the manifest before signing it.
"""
import base64
import datetime
import hashlib
import json
import os
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GENESIS = "0" * 64
EXPORT_FORMAT = "pg.evidence.export.v1"


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical(obj):
    """RFC 8785 for the values these tests use (strings, integers, null, booleans, arrays, objects)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


class Signer:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.x = b64url(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        members = canonical({"crv": "Ed25519", "kty": "OKP", "x": self.x})
        self.kid = b64url(hashlib.sha256(members.encode("utf-8")).digest())

    def sign(self, data):
        return b64url(self.key.sign(data))

    def jwk(self):
        return {"kty": "OKP", "crv": "Ed25519", "x": self.x, "kid": self.kid, "use": "sig", "alg": "EdDSA",
                "status": "active"}


def body(tenant, seq, prev, **extra):
    b = {"schema": "pg.evidence.v1", "id": "00000000-0000-4000-8000-%012d" % seq, "tenant_id": tenant,
         "decision_type": "edge_authz", "subject": "demo-user", "outcome": "allow", "reasons": [],
         "policy": {"pack_version": "test", "bundle_revision": None, "decision_id": "decision-%d" % seq},
         "input_sha256": None, "payload": {"n": seq},
         "created_at": "2026-11-07T12:%02d:00.000Z" % (seq % 60), "seq": seq, "prev_hash": prev}
    b.update(extra)
    return b


def record(signer, signed_body):
    text = canonical(signed_body)
    return {"id": signed_body["id"], "seq": signed_body["seq"], "canonical": text,
            "signature": signer.sign(text.encode("utf-8")), "kid": signer.kid,
            "body_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "prev_hash": signed_body["prev_hash"],
            "decided_at": "2026-11-07T12:00:00.000000Z", "recorded_at": "2026-11-07T12:00:00.000000Z",
            "in_window": True}


def resign(rec, signer, text=None):
    """The record with `text` (default: its own canonical) as canonical, re-hashed and re-signed by `signer`."""
    text = rec["canonical"] if text is None else text
    out = dict(rec, canonical=text, signature=signer.sign(text.encode("utf-8")), kid=signer.kid,
               body_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
    return out


def chain(signer, tenant, n, first=1, prev=GENESIS, bodies=None):
    """Records seq first..first+n-1, each linked to the previous; bodies: {seq: extra body fields}."""
    out = []
    for seq in range(first, first + n):
        rec = record(signer, body(tenant, seq, prev, **(bodies or {}).get(seq, {})))
        out.append(rec)
        prev = rec["body_sha256"]
    return out


def jsonl(lines):
    return "".join(json.dumps(line, separators=(",", ":")) + "\n" for line in lines).encode("utf-8")


def pack_files(records, signer, tenant, jwks_signers=None, manifest_signer=None, edit=None, extra_files=None,
               records_bytes=None, jwks_bytes=None):
    """{name: bytes} of a pack. The manifest describes `records` as given (seq range from the lowest to the highest
    seq, chain head at the highest), then `edit(manifest)` may change it, then it is signed by `manifest_signer`
    (default `signer`). extra_files (e.g. anchors/...) are declared in the manifest's files."""
    records_bytes = jsonl(records) if records_bytes is None else records_bytes
    jwks = jwks_bytes if jwks_bytes is not None else json.dumps(
        {"keys": [s.jwk() for s in (jwks_signers or [signer])]}).encode("utf-8")
    manifest_signer = manifest_signer or signer
    good = [r for r in records if isinstance(r, dict) and isinstance(r.get("seq"), int)]
    by_seq = sorted(good, key=lambda r: r["seq"])
    files = {"records.jsonl": {"sha256": hashlib.sha256(records_bytes).hexdigest(), "bytes": len(records_bytes)},
             "jwks.json": {"sha256": hashlib.sha256(jwks).hexdigest(), "bytes": len(jwks)}}
    for name, data in (extra_files or {}).items():
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    manifest = {
        "format": EXPORT_FORMAT, "export_id": "00000000-0000-4000-8000-00000000e001", "tenant": tenant,
        "window": {"from": "2026-11-07T00:00:00.000000Z", "to": "2026-11-07T23:59:59.000000Z"},
        "seq_range": {"first": by_seq[0]["seq"], "last": by_seq[-1]["seq"]} if by_seq else None,
        "record_count": len(records), "in_window_count": len(records),
        "anchor": by_seq[0]["prev_hash"] if by_seq else None,
        "chain_head": {"seq": by_seq[-1]["seq"], "hash": by_seq[-1]["body_sha256"]} if by_seq else None,
        "created_at": "2026-11-07T23:59:59.000Z", "bundle_revisions": [], "files": files,
        "anchoring": {"present": False}, "signing_kid": manifest_signer.kid,
        "exported_by": {"credential": "test", "sub": None},
    }
    if edit is not None:
        edit(manifest)
    manifest_bytes = canonical(manifest).encode("utf-8")
    out = {"records.jsonl": records_bytes, "jwks.json": jwks, "manifest.json": manifest_bytes,
           "manifest.sig": (manifest_signer.sign(manifest_bytes) + "\n").encode("ascii")}
    out.update(extra_files or {})
    return out


def write_zip(path, files, duplicates=()):
    """A zip of `files`; each (name, data) in `duplicates` is added as a second entry of that name."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
        for name, data in duplicates:
            z.writestr(name, data)
    return path


def write_dir(path, files):
    for name, data in files.items():
        full = os.path.join(path, *name.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)
    return path


# --- anchors: a throwaway RFC 3161 TSA and pg.anchor.v1 statements ------------------------------------------------

TENANT_DOMAIN = "pg.anchor.tenant.v1:"
TSA_POLICY = "1.3.6.1.4.1.99999.77"


def iso_ms(t):
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


class TestTsa:
    """An Ed25519 root and a time-stamping signer under it; token(digest, gen_time) is an RFC 3161 TimeStampResp
    with whatever genTime the test asks for. Needs asn1crypto."""

    def __init__(self, name="test-tsa"):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        self.name = name
        self.root_key = Ed25519PrivateKey.generate()
        self.key = Ed25519PrivateKey.generate()
        start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Root")])
        self.root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                     .public_key(self.root_key.public_key()).serial_number(1).not_valid_before(start)
                     .not_valid_after(end).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(self.root_key, None))
        self.cert = (x509.CertificateBuilder()
                     .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Signer")]))
                     .issuer_name(root_name).public_key(self.key.public_key()).serial_number(2)
                     .not_valid_before(start).not_valid_after(end)
                     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
                     .sign(self.root_key, None))
        self._der = serialization.Encoding.DER
        self.spki_sha256 = hashlib.sha256(self.root.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.serial = 0

    def roots_file(self, path):
        with open(path, "w") as f:
            json.dump({"format": "pg.tsa-roots.v1", "roots": [{"name": self.name, "spki_sha256": self.spki_sha256,
                                                                "policy_oids": [TSA_POLICY]}]}, f)
        return path

    def token(self, digest, gen_time):
        from asn1crypto import algos, cms, tsp
        from asn1crypto import x509 as ax509
        self.serial += 1
        tst_der = tsp.TSTInfo({
            "version": "v1", "policy": TSA_POLICY, "serial_number": self.serial, "gen_time": gen_time,
            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        }).dump()
        signer_der = self.cert.public_bytes(self._der)
        signer = ax509.Certificate.load(signer_der)
        attrs = cms.CMSAttributes([
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]},
            {"type": "signing_certificate_v2", "values": [{"certs": [{
                "hash_algorithm": {"algorithm": "sha256"}, "cert_hash": hashlib.sha256(signer_der).digest()}]}]},
        ])
        signed = bytearray(attrs.dump())
        signed[0] = 0x31
        info = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
                "issuer": signer.issuer, "serial_number": signer.serial_number}}),
            "digest_algorithm": {"algorithm": "sha256"}, "signed_attrs": attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "ed25519"}),
            "signature": self.key.sign(bytes(signed)),
        })
        signed_data = cms.SignedData({
            "version": "v3", "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info", "content": cms.ParsableOctetString(tst_der)},
            "certificates": [signer, ax509.Certificate.load(self.root.public_bytes(self._der))],
            "signer_infos": [info],
        })
        return tsp.TimeStampResp({
            "status": {"status": "granted"},
            "time_stamp_token": {"content_type": "signed_data", "content": signed_data},
        }).dump()


def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root_and_path(leaves, index):
    """RFC 9162 root of a power-of-two list of leaf data, and the inclusion path of leaves[index]."""
    level = [_leaf(d) for d in leaves]
    path = []
    while len(level) > 1:
        path.append(level[index ^ 1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return level[0], path


def anchor_files(records, signer, tenant, tsa, anchors, statement_signer=None, statement_edit=None,
                 other_proofs=None):
    """(extra_files, manifest edit) for anchors [(head_seq, gen_time)], numbered 1.. in order: each statement is
    signed by `statement_signer` (default `signer`), timestamped by `tsa` at gen_time, and holds this tenant's leaf
    (seq head_seq, that record's body_sha256) at index 0 of a 16-leaf tree, and another tenant's ("other") at index
    1. statement_edit(n, statement) may change a statement before it is signed. other_proofs, a list, receives the
    other tenant's real proof line for each anchor."""
    statement_signer = statement_signer or signer
    by_seq = {r["seq"]: r for r in records}
    tenant_sha256 = hashlib.sha256((TENANT_DOMAIN + tenant).encode("utf-8")).hexdigest()
    statements, proofs, tokens, files = [], [], [], {}
    prev = GENESIS
    for n, (head_seq, gen_time) in enumerate(anchors, start=1):
        leaf = canonical({"head_hash": by_seq[head_seq]["body_sha256"], "seq": head_seq,
                          "tenant_sha256": tenant_sha256, "v": 1})
        other = canonical({"head_hash": "ab" * 32, "seq": 100 + n,
                           "tenant_sha256": hashlib.sha256((TENANT_DOMAIN + "other").encode("utf-8")).hexdigest(),
                           "v": 1})
        leaves = [leaf.encode("utf-8"), other.encode("utf-8")] + [
            canonical({"pad": "%02x" % i * 32, "v": 1}).encode("utf-8") for i in range(2, 16)]
        root, path = merkle_root_and_path(leaves, 0)
        if other_proofs is not None:
            other_proofs.append({"anchor_seq": n, "leaf_index": 1, "tree_size": 16, "leaf_data": other,
                                 "path": [p.hex() for p in merkle_root_and_path(leaves, 1)[1]]})
        st = {"anchor_seq": n, "created_at": iso_ms(gen_time - datetime.timedelta(seconds=1)),
              "kid": statement_signer.kid, "merkle_root": root.hex(), "prev_statement_sha256": prev,
              "schema": "pg.anchor.v1", "tree_size": 16}
        if statement_edit is not None:
            statement_edit(n, st)
        text = canonical(st)
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        statements.append({"anchor_seq": n, "statement": text, "statement_sha256": sha,
                           "statement_signature": statement_signer.sign(text.encode("utf-8")),
                           "kid": statement_signer.kid})
        proofs.append({"anchor_seq": n, "leaf_index": 0, "tree_size": 16, "leaf_data": leaf,
                       "path": [p.hex() for p in path]})
        name = "anchors/tokens/%d-%s.tsr" % (n, tsa.name)
        files[name] = tsa.token(bytes.fromhex(sha), gen_time)
        tokens.append({"anchor_seq": n, "tsa": tsa.name, "file": name})
        prev = sha
    files["anchors/statements.jsonl"] = jsonl(statements)
    files["anchors/proofs.jsonl"] = jsonl(proofs)
    count = len(anchors)

    def edit(m):
        m["anchoring"] = {"present": True, "tenant_sha256": tenant_sha256, "first_anchor_seq": 1,
                          "last_anchor_seq": count, "anchors": count, "proofs": count, "tokens": tokens,
                          "tsa_certs": []}
    return files, edit
