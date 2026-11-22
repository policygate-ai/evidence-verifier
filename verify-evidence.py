#!/usr/bin/env python3
"""Offline verifier for PolicyGate decision evidence (pg.evidence.v1).

A PolicyGate deployment (the signer) records policy decisions as Ed25519-signed, hash-chained records, one chain per
tenant, and exports them as signed packs. This script checks such a pack with no network access, or (online mode) a
tenant's live chain.

Offline mode (--input <pack.zip | directory>) checks:
  * manifest.sig: Ed25519 over the exact bytes of manifest.json (stored in RFC 8785 canonical form) under the
    manifest's signing_kid, taken from the pack's jwks.json; every kid in jwks.json is the RFC 7638 thumbprint of its
    key
  * the sha256 of records.jsonl, jwks.json and every anchors/ file equal the manifest's files.*.sha256
  * every record: its signature (Ed25519 over the UTF-8 canonical bytes) under the key named by kid,
    sha256(canonical) == body_sha256, the signed body agrees with the record envelope (schema, id, tenant_id, seq,
    prev_hash), seq contiguous from seq_range.first, the first prev_hash equal to the manifest's anchor (64 zeros at
    seq 1), every prev_hash linking to the previous body_sha256, and seq_range / record_count
  * the manifest's chain_head: when it is the last exported seq, its hash is that record's body_sha256
A pack with no records (empty window) is valid when its manifest says so. The first failure is printed first.

Pinning the signer's key. A pack carries its own public keys (jwks.json), so by itself it proves only that whoever
made it holds the key inside it. Obtain the signer's key by a channel you trust and pin it, so that a pack re-signed
end to end with another key fails:
  --expect-kid KID   (repeatable) the manifest, every record and every anchor statement must be signed by one of these
                     keys (RFC 7638 thumbprints)
  --keys-file FILE   a JWKS obtained out of band; same effect, and every key the pack uses must be a key in FILE
Without either, a valid pack still exits 0, and the line after OK reads "KEY NOT PINNED: ..." naming the kid used.

Payment records: every payment.sign record (decision_type agent_spend) is also checked for internal consistency:
  * payload.authorization_sha256 recomputes from the eight signed values it covers: SHA-256 of RFC 8785 JCS over
    {network, asset, payer, pay_to, amount, nonce, valid_after, valid_before} (addresses and nonce lower-case)
  * payload.eip712.digest recomputes from the signed EIP-712 domain and authorization (EIP-3009
    TransferWithAuthorization)
  * payload.payer, payload.authorization.from and payload.signer.payer name the same address

Payment match (--input PACK --match-payment VALUE): proves an observed x402 PAYMENT-SIGNATURE was covered by a policy
decision. VALUE is the header's base64 PaymentPayload (x402 v2, exact/EVM). After the pack verifies as above, it
  * recomputes the authorization hash from the payload's network, asset, from, to, value, nonce and window,
  * finds the payment.sign record in the pack that signed that hash,
  * recomputes the EIP-712 digest from that record's signed domain and the payload's authorization, and
  * recovers the signer of the payload's signature (secp256k1, pure Python below: `cryptography` cannot recover a
    public key), checks that `cryptography` verifies the signature under the recovered key, and that the key's
    address is the payer the record names.
Prints MATCH with the record's id and seq, or NO MATCH: no policy decision in this pack covers the payment. A pack
covers only its time window; a NO MATCH for a payment outside it says nothing.

Anchors (packs from a deployment that anchors its evidence with RFC 3161 time-stamp authorities): with --tsa-roots
FILE (YOUR pinned TSA roots, see below; roots and certificates inside the pack are never trusted) it also checks
  * anchors/statements.jsonl: each statement's SHA-256, its Ed25519 signature, contiguous anchor_seq and
    prev_statement_sha256 chaining
  * anchors/proofs.jsonl: this tenant's leaf (SHA-256("pg.anchor.tenant.v1:" + tenant), seq, head hash), its RFC 9162
    inclusion proof to the statement's merkle_root, anchored seq never decreasing, and the head hash equal to the
    pack's record at that seq
  * anchors/tokens/*.tsr: RFC 3161 token for SHA-256(statement): status, imprint, ESS signing certificate, signer EKU,
    signature, a chain (certificates from the token and anchors/tsa-certs/) to a pinned root SPKI, every certificate
    valid at genTime, the policy OID pinned for that root; genTime never earlier than the previous anchor's
  * no record recorded before an anchor's genTime sits above the head that anchor saw (backdating), and no anchored
    seq is beyond the pack's chain head (deletion)
  * every anchor statement names the same kid as the line that carries it
  * an anchor whose head lies beyond the pack's last record covers nothing in the pack ("ANCHOR BEYOND THIS PACK")
It prints "ANCHORED: seq a..b covered by <tsa> at <time> (anchor n)" and "NOT YET ANCHORED: seq c..d (after <time>)".
When a record in an anchored range failed its own checks, the range prints "ANCHOR CHECKED, RECORDS FAILED: ..."
instead of ANCHORED (and the FAIL lines say why).

Audit mode: --require-anchors --anchored-since DATE (needs --tsa-roots). DATE is when the signer started anchoring;
take it from the organisation that runs PolicyGate through a separate channel, never from a pack. Then every record
whose signed created_at is at or after DATE must be covered by an anchor in the pack that verifies, with one exception,
the newest records waiting for the next anchor (the grace rule): an uncovered record passes only if its signed
created_at is before T + --anchor-interval (default 10m) + --anchor-grace (default 15m), where T is the TSA genTime of
the latest anchor in the pack that verifies AND whose proof for this tenant reaches its merkle_root with a head that
matches the pack's record (or precedes the pack's first record), or DATE when there is none. T comes from a TSA token
or from you, never from the manifest or the records, so removing anchors or proofs, or editing the manifest's
created_at, can only shrink the exception. In audit mode signed created_at must also never be more than 5 minutes
before that of any earlier seq. A failure names the first uncovered seq.
Pack invariants: a pack exported by PolicyGate always has the same anchor structure (one proof per anchor, one token
entry or more per anchor, files named as the export names them, ...; see pack_invariants). A pack that differs FAILS
in audit mode and prints "WARNING: pack invariant broken: ..." otherwise.
--previous-pack OLD: compares the seq ranges both packs hold and names the first record that changed.
Any failure prints "FAIL: first bad seq <n> (<why>)" first (when a seq is involved), then every problem.

TSA roots file (format pg.tsa-roots.v1), one entry per root you trust:
  {"format": "pg.tsa-roots.v1", "roots": [{"name": "...", "spki_sha256": "<64 lowercase hex>",
   "policy_oids": ["<the TSA's policy OID>"]}]}
  spki_sha256 is the SHA-256 of the root certificate's DER SubjectPublicKeyInfo; obtain the root from the TSA's own
  publication: openssl x509 -in root.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum

Online mode (--base-url, --tenant) fetches the deployment's public keys (GET /v1/evidence/keys) and the tenant's chain
(GET /v1/evidence/chain, with the read token from --token or POLICYGATE_EVIDENCE_READ_TOKEN) and runs the record
checks above, seq contiguous from --from-seq (genesis prev_hash at seq 1, else --expect-prev-hash). --expect-kid and
--keys-file apply. It exits 0 only if every check passes and at least one record was verified.

Exit codes: 0 valid (and MATCH), 1 verification failed or NO MATCH, 2 usage error.
Requirements: Python 3.11 or newer and `cryptography`; anchors also need `asn1crypto`. Pinned with hashes in
requirements-verify.txt: python3 -m pip install --require-hashes -r requirements-verify.txt

Usage:
  python3 verify-evidence.py --input evidence-example-bank.zip --expect-kid <signer kid>
  python3 verify-evidence.py --input evidence-example-bank.zip --keys-file signer-keys.json
  python3 verify-evidence.py --input evidence-example-bank.zip --expect-kid <kid> --match-payment @payment-signature.txt
  python3 verify-evidence.py --input evidence-example-bank.zip --expect-kid <kid> --tsa-roots tsa-roots.json \\
      --require-anchors --anchored-since 2026-11-07T16:00:00Z [--previous-pack older.zip]
  POLICYGATE_EVIDENCE_READ_TOKEN=... python3 verify-evidence.py --base-url https://policygate.example \\
      --tenant example-bank --expect-kid <kid>
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

SCHEMA = "pg.evidence.v1"
EXPORT_FORMAT = "pg.evidence.export.v1"
PACK_FILES = ("manifest.json", "manifest.sig", "jwks.json", "records.jsonl")
GENESIS = "0" * 64
PAGE_LIMIT = 500
ANCHOR_SCHEMA = "pg.anchor.v1"
TSA_ROOTS_FORMAT = "pg.tsa-roots.v1"
TENANT_DOMAIN = "pg.anchor.tenant.v1:"
ANCHOR_FILES = ("anchors/statements.jsonl", "anchors/proofs.jsonl")
MAX_SKEW = datetime.timedelta(minutes=5)

# Input limits: a pack (or a response) is untrusted input. Zip: at most MAX_ENTRIES entries, MAX_FILE bytes per file,
# MAX_TOTAL bytes in all, a compression ratio of at most MAX_RATIO for entries over 1 MiB, no absolute or ".." names,
# no symlinks. JSON: at most MAX_JSON bytes per document (MAX_LINE per JSON Lines line), nesting depth MAX_DEPTH.
MAX_ENTRIES = 50000
MAX_FILE = 1 << 30
MAX_TOTAL = 2 << 30
MAX_RATIO = 200
MAX_JSON = 32 << 20
MAX_LINE = 1 << 20
MAX_DEPTH = 64


class InputRejected(ValueError):
    """Untrusted input over a limit or of an unsafe shape (zip-slip, symlink, bomb, deep JSON)."""


def json_depth(text):
    """Deepest nesting of objects/arrays in a JSON text, counted without parsing (strings skipped)."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def load_json(data, what, max_bytes=MAX_JSON):
    """json.loads with a size and depth limit; raises InputRejected (a ValueError) or ValueError."""
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise InputRejected("%s: %d bytes, more than the limit %d" % (what, len(data), max_bytes))
        data = data.decode("utf-8")
    elif len(data) > max_bytes:
        raise InputRejected("%s: more than the limit of %d bytes" % (what, max_bytes))
    if json_depth(data) > MAX_DEPTH:
        raise InputRejected("%s: JSON nested deeper than %d" % (what, MAX_DEPTH))
    return json.loads(data)


def is_int(value):
    """A JSON integer (bool is not one, although Python says it is an int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def kind(value):
    """The JSON type of a parsed value, for failure messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if is_int(value) or isinstance(value, float):
        return "a number"
    return {str: "a string", list: "an array", dict: "an object"}.get(type(value), type(value).__name__)


def short_text(text, limit=160):
    """One line of printable ASCII, at most `limit` characters: untrusted text echoed into a message."""
    text = " ".join(str(text).split()).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def shape_problems(where, obj, spec):
    """[problem] for the fields of `obj` (a dict) whose type is not what `spec` {field: (test, wanted)} says."""
    out = []
    for field, (test, wanted) in spec.items():
        value = obj.get(field)
        if not test(value):
            out.append("%s%s is %s, expected %s" % (where, field, kind(value), wanted))
    return out


def safe_member_name(name):
    """A zip entry name that can't escape the pack: relative, no '..', no backslash, no NUL, not empty."""
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return False
    return all(part not in ("", "..") for part in name.rstrip("/").split("/"))


def check_zip(z, path):
    """Rejects a zip that holds unsafe or oversized entries, before anything is read from it."""
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise InputRejected("%s: %d entries, more than %d" % (path, len(infos), MAX_ENTRIES))
    total = 0
    seen = set()
    for info in infos:
        if info.filename in seen:
            raise InputRejected("%s: duplicate entry name %r (unzip tools disagree on which one counts)"
                                % (path, info.filename))
        seen.add(info.filename)
        if not safe_member_name(info.filename):
            raise InputRejected("%s: unsafe entry name %r (absolute, '..', or backslash)" % (path, info.filename))
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise InputRejected("%s: entry %r is a symlink" % (path, info.filename))
        if info.file_size > MAX_FILE:
            raise InputRejected("%s: entry %r is %d bytes, more than %d" % (path, info.filename, info.file_size,
                                                                           MAX_FILE))
        if info.file_size > (1 << 20) and info.file_size > MAX_RATIO * max(info.compress_size, 1):
            raise InputRejected("%s: entry %r expands %d times (zip bomb?)" % (
                path, info.filename, info.file_size // max(info.compress_size, 1)))
        total += info.file_size
        if total > MAX_TOTAL:
            raise InputRejected("%s: more than %d bytes uncompressed" % (path, MAX_TOTAL))


def read_regular(full, rel):
    """A file of an unpacked pack: a regular file, not a symlink, within MAX_FILE."""
    st = os.lstat(full)
    if os.path.islink(full) or not (st.st_mode & 0o170000 == 0o100000):
        raise InputRejected("%s: not a regular file (symlink?)" % rel)
    if st.st_size > MAX_FILE:
        raise InputRejected("%s: %d bytes, more than %d" % (rel, st.st_size, MAX_FILE))
    with open(full, "rb") as f:
        return f.read()

# --- secp256k1 and Keccak-256, pure Python ----------------------------------------------------------------------
# Curve constants (SEC 2) written in 16-digit groups.
SECP_P = 2**256 - 2**32 - 977
SECP_N = int("FFFFFFFFFFFFFFFF" "FFFFFFFFFFFFFFFE" "BAAEDCE6AF48A03B" "BFD25E8CD0364141", 16)
SECP_G = (int("79BE667EF9DCBBAC" "55A06295CE870B07" "029BFCDB2DCE28D9" "59F2815B16F81798", 16),
          int("483ADA7726A3C465" "5DA4FBFC0E1108A8" "FD17B448A6855419" "9C47D08FFB10D4B8", 16))


def _ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP_P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, SECP_P) % SECP_P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, SECP_P) % SECP_P
    x = (m * m - a[0] - b[0]) % SECP_P
    return x, (m * (a[0] - x) - a[1]) % SECP_P


def _ec_mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        k >>= 1
    return result


_KECCAK_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
              0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
              0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
              0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
              0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
               [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _keccak_f(a):
    for rc in _KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M64 if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    """Keccak-256 with the original padding Ethereum uses (not FIPS 202 SHA3-256, which hashlib has)."""
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def eth_address(point):
    return "0x" + keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def recover_public_key(digest, signature):
    """SEC 1 v2 §4.1.6 recovery from a 65-byte r || s || v signature (v 27/28 or 0/1); None if it isn't one."""
    if len(signature) != 65 or len(digest) != 32:
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    rec_id = v - 27 if v >= 27 else v
    if rec_id not in (0, 1) or not 0 < r < SECP_N or not 0 < s < SECP_N:
        return None
    alpha = (pow(r, 3, SECP_P) + 7) % SECP_P
    y = pow(alpha, (SECP_P + 1) // 4, SECP_P)
    if y * y % SECP_P != alpha:
        return None
    if y % 2 != rec_id:
        y = SECP_P - y
    z = int.from_bytes(digest, "big")
    r_inv = pow(r, -1, SECP_N)
    point = _ec_add(_ec_mul(s * r_inv % SECP_N, (r, y)), _ec_mul((-z * r_inv) % SECP_N, SECP_G))
    return point


def cryptography_verifies(point, digest, signature):
    """Independent check of the recovery: `cryptography`'s ECDSA verifies the signature under the recovered key."""
    try:
        key = ec.EllipticCurvePublicNumbers(point[0], point[1], ec.SECP256K1()).public_key()
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"))
        key.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- EIP-712 / EIP-3009 -------------------------------------------------------------------------------------------
EIP712_DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
TRANSFER_WITH_AUTHORIZATION_TYPE = (b"TransferWithAuthorization(address from,address to,uint256 value,"
                                    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)")


def _uint256(value):
    return int(value).to_bytes(32, "big")


def _address(value):
    raw = bytes.fromhex(value[2:] if value.lower().startswith("0x") else value)
    if len(raw) != 20:
        raise ValueError("not a 20-byte address: %r" % value)
    return b"\x00" * 12 + raw


def _bytes32(value):
    raw = bytes.fromhex(value[2:] if value.lower().startswith("0x") else value)
    if len(raw) != 32:
        raise ValueError("not 32 bytes: %r" % value)
    return raw


def eip712_digest(domain, authorization):
    """domain: {name, version, chain_id, verifying_contract}; authorization: {from, to, value, valid_after,
    valid_before, nonce} (decimal strings, 0x hex)."""
    separator = keccak256(keccak256(EIP712_DOMAIN_TYPE) + keccak256(domain["name"].encode("utf-8"))
                          + keccak256(domain["version"].encode("utf-8")) + _uint256(domain["chain_id"])
                          + _address(domain["verifying_contract"]))
    struct = keccak256(keccak256(TRANSFER_WITH_AUTHORIZATION_TYPE) + _address(authorization["from"])
                       + _address(authorization["to"]) + _uint256(authorization["value"])
                       + _uint256(authorization["valid_after"]) + _uint256(authorization["valid_before"])
                       + _bytes32(authorization["nonce"]))
    return keccak256(b"\x19\x01" + separator + struct)


def authorization_sha256(network, asset, payer, pay_to, amount, nonce, valid_after, valid_before):
    """SHA-256 of RFC 8785 JCS over the eight values a payment.sign record's authorization_sha256 covers. All are
    ASCII strings, so JCS is sorted keys and no whitespace; addresses and the nonce lower-case."""
    doc = {"network": network, "asset": asset.lower(), "payer": payer.lower(), "pay_to": pay_to.lower(),
           "amount": str(amount), "nonce": nonce.lower(), "valid_after": str(valid_after),
           "valid_before": str(valid_before)}
    return hashlib.sha256(json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()


def asset_contract(asset_id):
    """eip155:<chain>/erc20:<contract> → contract; None otherwise."""
    if not isinstance(asset_id, str) or "/erc20:" not in asset_id:
        return None
    return asset_id.split("/erc20:", 1)[1]


def payment_sign_failures(body, where):
    """Internal consistency of one payment.sign record (see the module docstring); [] for any other record."""
    if body.get("decision_type") != "agent_spend":
        return []
    p = body.get("payload")
    if not isinstance(p, dict) or p.get("event") != "payment.sign":
        return []
    failures = []
    try:
        auth = p["authorization"]
        expected = authorization_sha256(p["network"], asset_contract(p["asset_id"]), auth["from"], auth["to"],
                                        auth["value"], auth["nonce"], auth["valid_after"], auth["valid_before"])
        if expected != p.get("authorization_sha256"):
            failures.append("%s: payment authorization_sha256 %s does not recompute (%s)"
                            % (where, p.get("authorization_sha256"), expected))
        if auth["from"].lower() != str(p.get("payer")).lower() \
                or str((p.get("signer") or {}).get("payer")).lower() != str(p.get("payer")).lower():
            failures.append("%s: payment payer, authorization.from and signer.payer differ" % where)
        pay_to = str(p.get("pay_to")).rsplit(":", 1)[-1]  # CAIP-10 eip155:<chain>:<address>
        if auth["value"] != p.get("amount_units") or auth["to"].lower() != pay_to.lower():
            failures.append("%s: payment authorization value/to differ from amount_units/pay_to" % where)
        digest = "0x" + eip712_digest(p["eip712"]["domain"], auth).hex()
        if digest != p["eip712"].get("digest"):
            failures.append("%s: payment eip712.digest %s does not recompute (%s)"
                            % (where, p["eip712"].get("digest"), digest))
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as e:
        failures.append("%s: payment.sign record is missing a signed field (%s)" % (where, short_text(e)))
    return failures


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def http_get_json(url, token=None, timeout=30):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return load_json(response.read(MAX_JSON + 1), url)


def load_keys(jwks):
    """Returns {kid: Ed25519PublicKey}; raises ValueError on a malformed key or kid mismatch."""
    keys = {}
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys", []), list):
        raise ValueError("not a JWKS ({\"keys\": [...]})")
    for jwk in jwks.get("keys", []):
        if not isinstance(jwk, dict):
            raise ValueError("a JWKS key is %s, not an object" % kind(jwk))
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        x = jwk.get("x")
        if not isinstance(x, str):
            raise ValueError("a JWKS key's x is %s, not a string" % kind(x))
        members = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
        thumbprint = b64url_encode(hashlib.sha256(members.encode("utf-8")).digest())
        if jwk.get("kid") != thumbprint:
            raise ValueError("JWKS kid %s is not the RFC 7638 thumbprint %r"
                             % (short_text(repr(jwk.get("kid"))), thumbprint))
        keys[thumbprint] = Ed25519PublicKey.from_public_bytes(b64url_decode(x))
    if not keys:
        raise ValueError("JWKS contains no Ed25519 keys")
    return keys


KID_FORMAT = re.compile(r"[A-Za-z0-9_-]{43}")


def raw_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KeyPin:
    """The signer keys the user trusts: --expect-kid values and/or the keys of a --keys-file JWKS. A kid passes only
    if it is in every set given; with a keys file, the pack's key of that kid must also be the file's key."""

    def __init__(self, kids=None, keys=None, keys_path=None):
        self.kids = set(kids) if kids else None
        self.keys = keys
        self.keys_path = keys_path

    def problem(self, kid, pack_keys=None):
        """None if `kid` is pinned, else why not (for a failure message)."""
        if not isinstance(kid, str):
            return "the kid is %s, not a string" % kind(kid)
        if self.kids is not None and kid not in self.kids:
            return "kid %r is not one of --expect-kid" % short_text(kid)
        if self.keys is not None:
            if kid not in self.keys:
                return "kid %r is not in --keys-file %s" % (short_text(kid), self.keys_path)
            pack_key = (pack_keys or {}).get(kid)
            if pack_key is not None and raw_public(pack_key) != raw_public(self.keys[kid]):
                return "the pack's key %r differs from the one in --keys-file %s" % (kid, self.keys_path)
        return None


def load_keys_file(path):
    """A JWKS obtained out of band (--keys-file): a regular file, at most MAX_LINE bytes; raises ValueError/OSError."""
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("%s: not a regular file" % path)
    with open(path, "rb") as f:
        data = f.read(MAX_LINE + 1)
    doc = load_json(data, path, MAX_LINE)
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("%s: not a JWKS ({\"keys\": [...]})" % path)
    try:
        return load_keys(doc)
    except (KeyError, TypeError, AttributeError) as e:
        raise ValueError("%s: malformed key (%s)" % (path, short_text(e)))


def fetch_chain(base_url, tenant, from_seq, token):
    records = []
    next_seq = from_seq
    while True:
        query = urllib.parse.urlencode({"tenant": tenant, "fromSeq": next_seq, "limit": PAGE_LIMIT})
        page = http_get_json("%s/v1/evidence/chain?%s" % (base_url, query), token)["records"]
        records.extend(page)
        if len(page) < PAGE_LIMIT:
            return records
        next_seq = page[-1]["seq"] + 1


RECORD_FIELDS = {
    "id": (lambda v: isinstance(v, str), "a string"),
    "seq": (is_int, "an integer"),
    "canonical": (lambda v: isinstance(v, str), "a string"),
    "signature": (lambda v: isinstance(v, str), "a string"),
    "kid": (lambda v: isinstance(v, str), "a string"),
    "body_sha256": (lambda v: isinstance(v, str), "a string"),
    "prev_hash": (lambda v: isinstance(v, str), "a string"),
}


def record_problems(record):
    """Why a record line (or a response record) is not one: missing fields or wrong types; [] when it is."""
    if not isinstance(record, dict):
        return ["not an object (%s)" % kind(record)]
    missing = [f for f in RECORD_FIELDS if f not in record]
    if missing:
        return ["missing %s" % ", ".join(missing)]
    return shape_problems("", record, RECORD_FIELDS)


def verify_chain(records, keys, tenant, from_seq, expected_prev=None, allow_empty=False, pin=None):
    """Returns a list of failure strings (empty == chain valid)."""
    failures = []
    if not records:
        return [] if allow_empty else ["no records returned for tenant %r from seq %d" % (tenant, from_seq)]

    expected_seq = from_seq
    prev_hash = GENESIS if from_seq == 1 else expected_prev
    for number, record in enumerate(records, start=1):
        problems = record_problems(record)
        if problems:
            failures.append("record %d (expected seq %d): not a valid record (%s)"
                            % (number, expected_seq, "; ".join(problems)))
            prev_hash = None
            expected_seq += 1
            continue
        seq = record.get("seq")
        where = "seq %s (id %s)" % (seq, short_text(record.get("id")))
        canonical_bytes = record["canonical"].encode("utf-8")
        if pin is not None:
            why = pin.problem(record.get("kid"), keys)
            if why:
                failures.append("%s: not signed by a pinned key: %s" % (where, why))

        if seq != expected_seq:
            failures.append("%s: expected seq %d (gap or reorder)" % (where, expected_seq))
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        if digest != record["body_sha256"]:
            failures.append("%s: sha256(canonical)=%s != body_sha256=%s" % (where, digest, record["body_sha256"]))
        if prev_hash is not None and record["prev_hash"] != prev_hash:
            failures.append("%s: prev_hash %s does not link to previous body_sha256 %s"
                            % (where, record["prev_hash"], prev_hash))

        key = keys.get(record.get("kid"))
        if key is None:
            failures.append("%s: unknown kid %r" % (where, short_text(record.get("kid"))))
        else:
            try:
                key.verify(b64url_decode(record["signature"]), canonical_bytes)
            except (InvalidSignature, ValueError):
                failures.append("%s: signature INVALID" % where)

        unparsed = object()
        try:
            body = load_json(record["canonical"], where, MAX_LINE)
        except ValueError:
            body = unparsed
            failures.append("%s: canonical is not valid JSON" % where)
        if body is not unparsed and not isinstance(body, dict):
            failures.append("%s: canonical is %s, not a JSON object" % (where, kind(body)))
        elif body is not unparsed:
            for field, expected in (("schema", SCHEMA), ("id", record.get("id")), ("tenant_id", tenant),
                                    ("seq", seq), ("prev_hash", record["prev_hash"])):
                if body.get(field) != expected:
                    failures.append("%s: signed body %s=%s != %r" % (where, field,
                                                                    short_text(repr(body.get(field))), expected))
            try:
                parse_time(body.get("created_at"))
            except (ValueError, AttributeError, TypeError):
                failures.append("%s: signed created_at %s is not an RFC 3339 time with a time zone"
                                % (where, short_text(repr(body.get("created_at")))))
            failures.extend(payment_sign_failures(body, where))

        prev_hash = record["body_sha256"]
        expected_seq = seq + 1
    return failures


def read_pack(path):
    """Returns {name: bytes} for the pack files present in a zip or a directory."""
    files = {}
    if os.path.isdir(path):
        total = 0
        for name in PACK_FILES:
            full = os.path.join(path, name)
            if os.path.lexists(full):
                files[name] = read_regular(full, name)
        anchors_dir = os.path.join(path, "anchors")
        if os.path.islink(anchors_dir):
            raise InputRejected("anchors: is a symlink")
        for root, dirs, names in os.walk(anchors_dir, followlinks=False):
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    raise InputRejected("%s: is a symlink" % os.path.relpath(os.path.join(root, d), path))
            for n in names:
                full = os.path.join(root, n)
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                files[rel] = read_regular(full, rel)
                if len(files) > MAX_ENTRIES:
                    raise InputRejected("%s: more than %d files" % (path, MAX_ENTRIES))
        for data in files.values():
            total += len(data)
        if total > MAX_TOTAL:
            raise InputRejected("%s: more than %d bytes" % (path, MAX_TOTAL))
        return files
    with zipfile.ZipFile(path) as z:
        check_zip(z, path)
        names = set(z.namelist())
        for name in PACK_FILES:
            if name in names:
                files[name] = z.read(name)
        for name in sorted(names):
            if name.startswith("anchors/") and not name.endswith("/"):
                files[name] = z.read(name)
    return files


def parse_records(data):
    """records.jsonl → (records, failures); a line that is not a JSON object is named by its line number."""
    records, failures = [], []
    for number, line in enumerate(data.split(b"\n"), start=1):
        if not line:
            continue
        try:
            record = load_json(line, "records.jsonl line %d" % number, MAX_LINE)
            problems = record_problems(record)
            if problems:
                raise ValueError("; ".join(problems))
        except ValueError as e:
            failures.append("records.jsonl line %d: not a valid record (%s)" % (number, short_text(e)))
            continue
        records.append(record)
    return records, failures


def verify_pack(path, pin=None):
    """Returns (failures, manifest); failures in the order found, the first one first."""
    failures, manifest, _ = verify_pack_records(path, pin)
    return failures, manifest


def verify_pack_records(path, pin=None):
    """verify_pack, also returning the parsed records (only meaningful when there are no failures)."""
    failures, manifest, records, _ = verify_pack_files(path, pin)
    return failures, manifest, records


def verify_pack_files(path, pin=None):
    """verify_pack_records, also returning the pack's files {name: bytes}. The manifest is None when it could not be
    trusted or is malformed, so nothing downstream reads it."""
    try:
        files = read_pack(path)
    except InputRejected as e:
        return ["REJECTED: %s" % e], None, [], {}
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError,
            NotImplementedError) as e:
        return ["%s: cannot read pack (%s)" % (path, short_text(e))], None, [], {}
    failures, manifest, records = _verify_pack_files(files, pin)
    return failures, manifest, records, files


def _optional(test):
    return lambda v: v is None or test(v)


def _is_str(v):
    return isinstance(v, str)


def _is_hex64(v):
    return isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) is not None


MANIFEST_FIELDS = {
    "tenant": (lambda v: isinstance(v, str) and v != "", "a non-empty string"),
    "seq_range": (_optional(lambda v: isinstance(v, dict)), "an object or null"),
    "record_count": (is_int, "an integer"),
    "anchor": (_optional(_is_str), "a string or null"),
    "chain_head": (_optional(lambda v: isinstance(v, dict)), "an object or null"),
    "files": (lambda v: isinstance(v, dict), "an object"),
    "anchoring": (_optional(lambda v: isinstance(v, dict)), "an object or null"),
    "window": (_optional(lambda v: isinstance(v, dict)), "an object or null"),
    "created_at": (_is_str, "a string"),
}


def manifest_problems(m):
    """Wrong types in a (signed) manifest: [problem]. A manifest that passes may be read without further checks."""
    out = shape_problems("manifest.json: ", m, MANIFEST_FIELDS)
    if out:
        return out
    if m.get("seq_range") is not None:
        out += shape_problems("manifest.json: seq_range.", m["seq_range"],
                              {"first": (is_int, "an integer"), "last": (is_int, "an integer")})
    if m.get("chain_head") is not None:
        out += shape_problems("manifest.json: chain_head.", m["chain_head"],
                              {"seq": (is_int, "an integer"), "hash": (_is_str, "a string")})
    if m.get("window") is not None:
        out += shape_problems("manifest.json: window.", m["window"],
                              {"from": (_optional(_is_str), "a string"), "to": (_optional(_is_str), "a string")})
    for name, entry in m["files"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
            out.append("manifest.json: files[%r] is %s, expected an object with a sha256 string"
                       % (short_text(name), kind(entry)))
    anchoring = m.get("anchoring") or {}
    if "present" in anchoring and not isinstance(anchoring["present"], bool):
        out.append("manifest.json: anchoring.present is %s, expected a boolean" % kind(anchoring["present"]))
    elif anchoring.get("present"):
        out += shape_problems("manifest.json: anchoring.", anchoring, {
            "first_anchor_seq": (is_int, "an integer"), "last_anchor_seq": (is_int, "an integer"),
            "tokens": (_optional(lambda v: isinstance(v, list)), "an array")})
        for i, t in enumerate(anchoring.get("tokens") or []):
            if not isinstance(t, dict):
                out.append("manifest.json: anchoring.tokens[%d] is %s, expected an object" % (i, kind(t)))
            else:
                out += shape_problems("manifest.json: anchoring.tokens[%d]." % i, t, {
                    "anchor_seq": (is_int, "an integer"), "file": (_is_str, "a string"),
                    "tsa": (_optional(_is_str), "a string")})
    return out


def statement_kid_failures(files, pin, keys):
    """With a pin: every anchor statement in the pack must be signed by a pinned key (checked with or without
    --tsa-roots; a statement whose kid can't be read fails)."""
    data = files.get("anchors/statements.jsonl")
    if pin is None or data is None:
        return []
    failures = []
    for number, line in enumerate(data.split(b"\n"), start=1):
        if not line.strip():
            continue
        try:
            obj = load_json(line, "anchors/statements.jsonl line %d" % number, MAX_LINE)
        except ValueError as e:
            failures.append("anchors/statements.jsonl line %d: not JSON (%s)" % (number, short_text(e)))
            continue
        kid = obj.get("kid") if isinstance(obj, dict) else None
        why = pin.problem(kid, keys)
        if why:
            failures.append("anchors/statements.jsonl line %d: statement not signed by a pinned key: %s"
                            % (number, why))
    return failures


def _verify_pack_files(files, pin=None):
    missing = [name for name in PACK_FILES if name not in files]
    if missing:
        return ["%s: missing from the pack" % name for name in missing], None, []

    try:
        keys = load_keys(load_json(files["jwks.json"], "jwks.json", MAX_LINE))
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        return ["jwks.json: %s" % short_text(e)], None, []
    try:
        manifest = load_json(files["manifest.json"], "manifest.json")
        if not isinstance(manifest, dict):
            raise ValueError("not an object")
    except ValueError as e:
        return ["manifest.json: not valid JSON (%s)" % short_text(e)], None, []

    signing_kid = manifest.get("signing_kid")
    if not isinstance(signing_kid, str):
        return ["manifest.json: signing_kid is %s, expected a string" % kind(signing_kid)], None, []
    key = keys.get(signing_kid)
    if key is None:
        return ["manifest.sig: signing_kid %r not in jwks.json" % short_text(signing_kid)], None, []
    try:
        key.verify(b64url_decode(files["manifest.sig"].decode("ascii").strip()), files["manifest.json"])
    except (InvalidSignature, ValueError, UnicodeDecodeError):
        return ["manifest.sig: signature INVALID over manifest.json"], None, []
    if pin is not None:
        why = pin.problem(signing_kid, keys)
        if why:
            return ["manifest.sig: the manifest is not signed by a pinned key: %s" % why], None, []
    if manifest.get("format") != EXPORT_FORMAT:
        return ["manifest.json: format %s, expected %r" % (short_text(repr(manifest.get("format"))),
                                                           EXPORT_FORMAT)], None, []
    shape = manifest_problems(manifest)
    if shape:
        return shape, None, []

    failures = statement_kid_failures(files, pin, keys)
    declared = manifest.get("files") or {}
    jwks_sha = hashlib.sha256(files["jwks.json"]).hexdigest()
    if (declared.get("jwks.json") or {}).get("sha256") != jwks_sha:
        failures.append("jwks.json: sha256 %s does not match the manifest" % jwks_sha)

    records, failures_in_lines = parse_records(files["records.jsonl"])
    failures.extend(failures_in_lines)
    tenant = manifest.get("tenant")
    seq_range = manifest.get("seq_range")
    count = manifest.get("record_count")
    if seq_range is None:
        if records or count != 0:
            failures.append("records.jsonl: %d record(s) but the manifest declares an empty pack" % len(records))
    else:
        first, last = seq_range.get("first"), seq_range.get("last")
        anchor = manifest.get("anchor")
        if not isinstance(first, int) or not isinstance(last, int) or first < 1 or last < first:
            failures.append("manifest.json: bad seq_range %r" % seq_range)
        elif not records:
            failures.append("records.jsonl: no records, the manifest declares seq %d..%d" % (first, last))
        else:
            if not isinstance(anchor, str) or len(anchor) != 64:
                failures.append("manifest.json: anchor %r is not a sha256 hex digest" % (anchor,))
                anchor = None
            elif first == 1 and anchor != GENESIS:
                failures.append("manifest.json: anchor of seq 1 must be the genesis hash")
            failures.extend(verify_chain(records, keys, tenant, first, anchor, pin=pin))
            got_last = records[-1].get("seq")
            if got_last != last:
                failures.append("records.jsonl: last seq %s, the manifest declares %d (records missing at the end?)"
                                % (got_last, last))
            head = manifest.get("chain_head") or {}
            if not isinstance(head.get("seq"), int) or head["seq"] < last:
                failures.append("manifest.json: chain_head %r is before the last exported seq %d" % (head, last))
            elif head["seq"] == last and head.get("hash") != records[-1].get("body_sha256"):
                failures.append("seq %d (id %s): body_sha256 is not the manifest's chain_head hash %s"
                                % (last, records[-1].get("id"), head.get("hash")))
        if count != len(records):
            failures.append("records.jsonl: %d record(s), the manifest declares record_count %r"
                            % (len(records), count))

    records_sha = hashlib.sha256(files["records.jsonl"]).hexdigest()
    if (declared.get("records.jsonl") or {}).get("sha256") != records_sha:
        failures.append("records.jsonl: sha256 %s does not match the manifest" % records_sha)
    for name in sorted(n for n in files if n.startswith("anchors/")):
        want = (declared.get(name) or {}).get("sha256")
        if want is None:
            failures.append("%s: in the pack but not declared in the manifest" % name)
        elif hashlib.sha256(files[name]).hexdigest() != want:
            failures.append("%s: sha256 does not match the manifest" % name)
    for name in sorted(n for n in declared if n.startswith("anchors/") and n not in files):
        failures.append("%s: declared in the manifest but missing from the pack" % name)
    return failures, manifest, records


# --- anchors -------------------------------------------------------------------------------------------------------

def parse_time(value):
    """RFC 3339 / ISO-8601 with Z or an offset → aware datetime (UTC)."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    t = datetime.datetime.fromisoformat(text)
    if t.tzinfo is None:
        raise ValueError("%r has no time zone" % value)
    return t.astimezone(datetime.timezone.utc)


def iso(t):
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_duration(value):
    """15m, 900s, 1h → timedelta."""
    m = re.fullmatch(r"([0-9]+)([smh])", str(value).strip())
    if not m:
        raise ValueError("duration %r: use e.g. 900s, 15m, 1h" % value)
    return datetime.timedelta(seconds=int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)])


def load_tsa_roots(path):
    """The auditor's root pins: [{name, spki_sha256, policy_oids}]; raises ValueError on a malformed file."""
    with open(path, "rb") as f:
        doc = load_json(f.read(MAX_LINE + 1), path, MAX_LINE)
    if not isinstance(doc, dict) or doc.get("format") != TSA_ROOTS_FORMAT:
        raise ValueError("%s: format must be %r" % (path, TSA_ROOTS_FORMAT))
    roots = []
    for r in doc.get("roots") or []:
        pin = str(r.get("spki_sha256", ""))
        oids = r.get("policy_oids")
        if not re.fullmatch(r"[0-9a-f]{64}", pin) or not r.get("name") or not isinstance(oids, list) or not oids:
            raise ValueError("%s: each root needs name, spki_sha256 (64 lowercase hex) and policy_oids" % path)
        roots.append({"name": r["name"], "spki_sha256": pin, "policy_oids": [str(o) for o in oids]})
    if not roots:
        raise ValueError("%s: no roots" % path)
    return roots


def merkle_leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_verify_inclusion(leaf_hash, index, size, path, root):
    """RFC 9162 §2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = merkle_node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = merkle_node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def spki_sha256(cert):
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _common_name(cert):
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return names[0].value if names else cert.subject.rfc4514_string()


def verify_tsa_token(der, digest, roots, pool):
    """Checks one RFC 3161 TimeStampResp for `digest` (bytes) against pinned roots. `pool`: x509 certificates that may
    serve as intermediates (never as roots). Returns {gen_time, policy, root, signer}; raises ValueError(why)."""
    try:
        from asn1crypto import tsp
    except ImportError:
        raise ValueError("asn1crypto is not installed (pip install --require-hashes -r requirements-verify.txt)")
    try:
        resp = tsp.TimeStampResp.load(der)
        status = resp["status"]["status"].native
        if status not in ("granted", "granted_with_mods"):
            raise ValueError("TSA status %s" % status)
        token = resp["time_stamp_token"]
        if token["content_type"].native != "signed_data":
            raise ValueError("token is not CMS SignedData")
        sd = token["content"]
        encap = sd["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise ValueError("eContentType is not id-ct-TSTInfo")
        tst_der = encap["content"].contents
        tst = tsp.TSTInfo.load(tst_der)
        imprint = tst["message_imprint"]
        if imprint["hash_algorithm"]["algorithm"].native != "sha256" \
                or imprint["hashed_message"].native != digest:
            raise ValueError("message imprint is not SHA-256 of this statement")
        gen_time = tst["gen_time"].native.astimezone(datetime.timezone.utc)
        policy = tst["policy"].dotted
        token_certs = []
        if sd["certificates"].native is not None:
            token_certs = [x509.load_der_x509_certificate(c.chosen.dump()) for c in sd["certificates"]]
        certs = token_certs + list(pool)
        infos = list(sd["signer_infos"])
        if len(infos) != 1:
            raise ValueError("expected one SignerInfo")
        si = infos[0]
        sid = si["sid"]
        if sid.name == "issuer_and_serial_number":
            serial, issuer = sid.chosen["serial_number"].native, sid.chosen["issuer"].dump()
            signer = next((c for c in certs if c.serial_number == serial
                           and c.issuer.public_bytes() == issuer), None)
        else:
            ski = sid.chosen.native
            signer = next((c for c in certs if _ski(c) == ski), None)
        if signer is None:
            raise ValueError("signer certificate not in the token nor in anchors/tsa-certs")
        digest_name = si["digest_algorithm"]["algorithm"].native
        if digest_name not in _HASHES:
            raise ValueError("digest algorithm %s not supported" % digest_name)
        attrs = {a["type"].native: a["values"] for a in si["signed_attrs"]}
        if attrs.get("content_type") is None or attrs["content_type"][0].native != "tst_info":
            raise ValueError("signed contentType is not TSTInfo")
        if attrs.get("message_digest") is None \
                or attrs["message_digest"][0].native != hashlib.new(digest_name, tst_der).digest():
            raise ValueError("messageDigest does not match the TSTInfo (content changed)")
        signer_der = signer.public_bytes(serialization.Encoding.DER)
        if "signing_certificate_v2" in attrs:
            cid = attrs["signing_certificate_v2"][0]["certs"][0]
            alg = cid["hash_algorithm"]["algorithm"].native or "sha256"
            if cid["cert_hash"].native != hashlib.new(alg, signer_der).digest():
                raise ValueError("ESS signing-certificate-v2 does not name the signer certificate")
        elif "signing_certificate" in attrs:
            if attrs["signing_certificate"][0]["certs"][0]["cert_hash"].native != hashlib.sha1(signer_der).digest():
                raise ValueError("ESS signing-certificate does not name the signer certificate")
        else:
            raise ValueError("no ESS signing-certificate attribute")
        signed = bytearray(si["signed_attrs"].dump())
        signed[0] = 0x31  # [0] IMPLICIT -> SET OF, as signed (RFC 5652 §5.4)
        sig = si["signature"].native
        key = signer.public_key()
        h = _HASHES[digest_name]()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                if si["signature_algorithm"]["algorithm"].native == "rsassa_pss":
                    params = si["signature_algorithm"]["parameters"]
                    ph = _HASHES[params["hash_algorithm"]["algorithm"].native]()
                    key.verify(sig, bytes(signed), padding.PSS(padding.MGF1(ph), params["salt_length"].native), ph)
                else:
                    key.verify(sig, bytes(signed), padding.PKCS1v15(), h)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(sig, bytes(signed), ec.ECDSA(h))
            elif isinstance(key, Ed25519PublicKey):
                key.verify(sig, bytes(signed))
            else:
                raise ValueError("signer key type not supported")
        except InvalidSignature:
            raise ValueError("token signature INVALID")
        try:
            eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound:
            raise ValueError("signer has no extended key usage")
        if not eku.critical or list(eku.value) != [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]:
            raise ValueError("signer EKU is not exactly a critical id-kp-timeStamping")
        root = _chain_to_pin(signer, certs, gen_time, roots)
        if policy not in root["policy_oids"]:
            raise ValueError("policy %s is not pinned for root %s" % (policy, root["name"]))
        return {"gen_time": gen_time, "policy": policy, "root": root["name"], "signer": _common_name(signer)}
    except ValueError:
        raise
    except Exception as e:  # malformed DER and the like: a bad token, never a crash
        raise ValueError("not a valid time-stamp token (%s)" % type(e).__name__)


def _ski(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return None


def _valid_at(cert, t):
    return cert.not_valid_before_utc <= t <= cert.not_valid_after_utc


def _issued_by(child, parent):
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def _chain_to_pin(signer, certs, gen_time, roots):
    pins = {r["spki_sha256"]: r for r in roots}
    cur = signer
    for depth in range(8):
        if not _valid_at(cur, gen_time):
            raise ValueError("certificate %s not valid at genTime" % _common_name(cur))
        if depth > 0:
            try:
                if not cur.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError("%s is not a CA" % _common_name(cur))
            except x509.ExtensionNotFound:
                raise ValueError("%s is not a CA" % _common_name(cur))
        root = pins.get(spki_sha256(cur))
        if root is not None:
            return root
        parent = next((c for c in certs if c is not cur and c.subject == cur.issuer and _issued_by(cur, c)), None)
        if parent is None:
            raise ValueError("no chain from %s to a pinned root (--tsa-roots)" % _common_name(cur))
        cur = parent
    raise ValueError("certificate chain too long")


def _jsonl(data, what):
    out = []
    for n, line in enumerate(data.split(b"\n"), 1):
        if line.strip():
            try:
                obj = load_json(line, "%s line %d" % (what, n), MAX_LINE)
                if not isinstance(obj, dict):
                    raise ValueError("not an object")
                out.append(obj)
            except ValueError as e:
                raise ValueError("%s line %d: %s" % (what, n, e))
    return out


def record_time(record):
    """When the signer recorded it: the signed body's created_at."""
    return parse_time(load_json(record["canonical"], "record", MAX_LINE)["created_at"])


STATEMENT_LINE_FIELDS = {
    "anchor_seq": (is_int, "an integer"),
    "statement": (_is_str, "a string"),
    "statement_sha256": (_is_str, "a string"),
    "statement_signature": (_is_str, "a string"),
    "kid": (_is_str, "a string"),
}
STATEMENT_FIELDS = {
    "anchor_seq": (is_int, "an integer"),
    "prev_statement_sha256": (_is_str, "a string"),
    "merkle_root": (_is_hex64, "64 lowercase hex"),
    "tree_size": (is_int, "an integer"),
    "created_at": (_is_str, "a string"),
}
PROOF_LINE_FIELDS = {
    "anchor_seq": (is_int, "an integer"),
    "leaf_index": (is_int, "an integer"),
    "tree_size": (is_int, "an integer"),
    "leaf_data": (_is_str, "a string"),
    "path": (lambda v: isinstance(v, list), "an array"),
}


def verify_anchors(manifest, files, records, keys, roots):
    """Returns (failures [(seq|None, why)], segments [(a, b, anchor)], anchors {seq: info}, last_valid).
    A segment's anchor: {anchor_seq, tsa, gen_time}. Only called with the pack's files already hash-checked.

    last_valid (the T of the grace rule) is the latest anchor that verifies (statement, signature, chaining, a TSA
    token under a pinned root) AND whose proof for this tenant reaches its merkle_root with a head that either
    matches the pack's record at that seq or precedes the pack's first record. An anchor without a checked proof
    proves nothing about this tenant, so it never dates anything. An anchor whose head lies beyond the pack's last
    record covers nothing in the pack (anchors[n]["beyond"] = that head): nothing binds the records it would cover."""
    failures = []
    info = manifest.get("anchoring") or {}
    tenant = manifest.get("tenant")
    seq_range = manifest.get("seq_range")
    first = seq_range["first"] if seq_range else None
    last = seq_range["last"] if seq_range else None
    by_seq = {r["seq"]: r for r in records}
    head_seq = (manifest.get("chain_head") or {}).get("seq")
    try:
        statement_lines = _jsonl(files.get("anchors/statements.jsonl", b""), "anchors/statements.jsonl")
        proof_lines = _jsonl(files.get("anchors/proofs.jsonl", b""), "anchors/proofs.jsonl")
    except ValueError as e:
        return [(None, short_text(e, 300))], [], {}, None
    statements = []
    for i, line in enumerate(statement_lines, start=1):
        problems = shape_problems("", line, STATEMENT_LINE_FIELDS)
        if problems:
            failures.append((None, "anchors/statements.jsonl line %d: %s" % (i, "; ".join(problems))))
        else:
            statements.append(line)
    proofs = {}
    for i, line in enumerate(proof_lines, start=1):
        problems = shape_problems("", line, PROOF_LINE_FIELDS)
        if not problems and not all(isinstance(x, str) for x in line["path"]):
            problems = ["path holds something other than strings"]
        if problems:
            failures.append((None, "anchors/proofs.jsonl line %d: %s" % (i, "; ".join(problems))))
        else:
            proofs.setdefault(line["anchor_seq"], line)  # a second proof for one anchor: see pack_invariants
    if not statements:
        failures.append((None, "manifest says anchors are present, but anchors/statements.jsonl holds no statement"))
        return failures, [], {}, None
    pool = []
    for name in sorted(n for n in files if n.startswith("anchors/tsa-certs/")):
        try:
            pool.append(x509.load_der_x509_certificate(files[name]))
        except ValueError:
            failures.append((None, "%s: not a DER certificate" % name))
    tokens = {}
    for t in info.get("tokens") or []:
        tokens.setdefault(t.get("anchor_seq"), []).append(t)

    anchors = {}
    prev = None
    for line in statements:
        n = line.get("anchor_seq")
        text = line.get("statement", "")
        where = "anchor %s" % n
        ok = True
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != line.get("statement_sha256"):
            failures.append((None, "%s: statement_sha256 does not match the statement" % where))
            ok = False
        try:
            st = load_json(text, where, MAX_LINE)
        except ValueError:
            failures.append((None, "%s: statement is not JSON" % where))
            prev = None
            continue
        problems = (["it is %s, not an object" % kind(st)] if not isinstance(st, dict)
                    else shape_problems("", st, STATEMENT_FIELDS))
        if problems:
            failures.append((None, "%s: malformed statement (%s)" % (where, "; ".join(problems))))
            prev = None
            continue
        if st.get("schema") != ANCHOR_SCHEMA or st.get("anchor_seq") != n:
            failures.append((None, "%s: not a %s statement for anchor %s" % (where, ANCHOR_SCHEMA, n)))
            ok = False
        if st.get("kid") != line.get("kid"):
            failures.append((None, "%s: the statement names kid %s, the line that carries it kid %s"
                             % (where, short_text(repr(st.get("kid"))), short_text(repr(line.get("kid"))))))
            ok = False
        key = keys.get(line.get("kid"))
        try:
            if key is None:
                raise InvalidSignature()
            key.verify(b64url_decode(line.get("statement_signature", "")), text.encode("utf-8"))
        except (InvalidSignature, ValueError):
            failures.append((None, "%s: statement signature INVALID (kid %s)" % (where, line.get("kid"))))
            ok = False
        if prev is not None:
            if n != prev["n"] + 1:
                failures.append((None, "anchor chain broken: anchor %s follows anchor %s (anchors missing)"
                                 % (n, prev["n"])))
                ok = False
            elif st.get("prev_statement_sha256") != prev["sha"]:
                failures.append((None, "anchor chain broken: anchor %s does not name anchor %s's statement"
                                 % (n, prev["n"])))
                ok = False
        elif n == 1 and st.get("prev_statement_sha256") != GENESIS:
            failures.append((None, "anchor 1: prev_statement_sha256 is not the genesis value"))
            ok = False
        created = None
        try:
            created = parse_time(st.get("created_at", ""))
        except (ValueError, AttributeError):
            failures.append((None, "%s: bad created_at" % where))
            ok = False
        best = None
        problems = []
        for t in tokens.get(n, []):
            try:
                v = verify_tsa_token(files.get(t.get("file"), b""), bytes.fromhex(line.get("statement_sha256", "")),
                                     roots, pool)
                if best is None or v["gen_time"] < best["gen_time"]:
                    best = v
            except ValueError as e:
                problems.append("%s: %s" % (t.get("tsa"), e))
        if best is None:
            failures.append((None, "%s: no valid TSA token (%s)" % (where, "; ".join(problems) or "none in the pack")))
            ok = False
        anchors[n] = {"anchor_seq": n, "sha": line.get("statement_sha256"), "statement": st, "ok": ok,
                      "created": created, "token": best, "tsa": best and "%s (%s)" % (best["root"], best["signer"]),
                      "gen_time": best and best["gen_time"]}
        prev = {"n": n, "sha": line.get("statement_sha256")}
    for n in sorted(k for k in proofs if k not in anchors):
        failures.append((None, "anchors/proofs.jsonl has a proof for anchor %s, whose statement is missing" % n))
    if info.get("first_anchor_seq") != statements[0].get("anchor_seq") \
            or info.get("last_anchor_seq") != statements[-1].get("anchor_seq"):
        failures.append((None, "anchors/statements.jsonl does not hold the manifest's anchors %s..%s"
                         % (info.get("first_anchor_seq"), info.get("last_anchor_seq"))))

    # time order, then the tenant's leaves
    segments = []
    covered = (first - 1) if first is not None else 0
    last_time = None
    last_head = None
    seen_proof = False
    expected_tenant = hashlib.sha256((TENANT_DOMAIN + str(tenant)).encode("utf-8")).hexdigest()
    last_valid = None
    for n in sorted(anchors):
        a = anchors[n]
        if a["gen_time"] is not None:
            if last_time is not None and a["gen_time"] < last_time:
                failures.append((None, "anchor %s: genTime %s is before the previous anchor's %s (time order)"
                                 % (n, iso(a["gen_time"]), iso(last_time))))
                a["ok"] = False
            if a["created"] is not None and a["gen_time"] < a["created"] - MAX_SKEW:
                failures.append((None, "anchor %s: timestamped at %s, before its statement was made (%s)"
                                 % (n, iso(a["gen_time"]), iso(a["created"]))))
                a["ok"] = False
            last_time = a["gen_time"]
        proof = proofs.get(n)
        if proof is None:
            if seen_proof:
                failures.append((None, "anchor %s: this tenant's leaf is missing (it was in earlier anchors)" % n))
            continue
        seen_proof = True
        try:
            leaf = load_json(proof["leaf_data"], "anchor %s leaf" % n, MAX_LINE)
            h, head_hash = leaf["seq"], leaf["head_hash"]
            if not is_int(h) or not isinstance(head_hash, str):
                raise ValueError("leaf seq / head_hash of the wrong type")
            path = [bytes.fromhex(x) for x in proof["path"]]
            root = bytes.fromhex(a["statement"]["merkle_root"])
        except (ValueError, KeyError, TypeError):
            failures.append((None, "anchor %s: malformed proof" % n))
            continue
        cover_from = covered + 1
        upto = h if isinstance(h, int) and h >= cover_from else cover_from
        if leaf.get("tenant_sha256") != expected_tenant or leaf.get("v") != 1:
            failures.append((cover_from, "anchor %s: the leaf is not this tenant's (another tenant's proof?)" % n,
                             upto))
            continue
        if proof.get("tree_size") != a["statement"].get("tree_size") or not merkle_verify_inclusion(
                merkle_leaf_hash(proof["leaf_data"].encode("utf-8")), proof.get("leaf_index", -1),
                a["statement"].get("tree_size", 0), path, root):
            failures.append((cover_from, "anchor %s: the inclusion proof does not reach the anchored merkle_root" % n,
                             upto))
            continue
        if not a["ok"]:
            failures.append((cover_from if h >= cover_from else None,
                             "anchor %s does not verify, so it covers nothing (see above)" % n, upto))
            continue
        if last_head is not None and h < last_head:
            failures.append((h + 1, "anchor %s saw head seq %d, an earlier anchor saw %d: records removed"
                             % (n, h, last_head)))
        last_head = h if last_head is None else max(last_head, h)
        if isinstance(head_seq, int) and h > head_seq:
            failures.append((head_seq + 1, "anchor %s at %s covers seq %d, but the chain ends at seq %d: "
                             "records deleted" % (n, iso(a["gen_time"]), h, head_seq)))
            continue
        if first is not None and h > last:
            # The pack ends before the head this anchor saw (the signed chain_head allows it): the records it would
            # cover are not bound by anything here, so it neither covers them nor dates the grace rule.
            a["beyond"] = h
            continue
        if first is not None and first <= h <= last:
            record = by_seq.get(h)
            if record is None or record.get("body_sha256") != head_hash:
                failures.append((cover_from, "seq %d does not match the head anchored at %s by %s (anchor %s): "
                                 "records %d..%d changed after they were anchored; --previous-pack names the exact "
                                 "one" % (h, iso(a["gen_time"]), a["tsa"], n, cover_from, h), h))
                continue
        # backdating: nothing above h may have been recorded before this anchor's time
        for r in records:
            if r["seq"] > h:
                try:
                    if record_time(r) < a["gen_time"] - MAX_SKEW:
                        failures.append((r["seq"], "recorded at %s, before anchor %s (%s) saw the chain end at "
                                         "seq %d: backdated" % (iso(record_time(r)), n, iso(a["gen_time"]), h)))
                        break
                except (ValueError, KeyError, TypeError, AttributeError):
                    pass
        last_valid = a
        if first is not None and h > covered and h >= first:
            segments.append((max(first, covered + 1), h, a))
            covered = h
    return failures, segments, anchors, last_valid

TOKEN_NAME = re.compile(r"anchors/tokens/([1-9][0-9]*)-([A-Za-z0-9._-]+)\.tsr")
CERT_NAME = re.compile(r"anchors/tsa-certs/([0-9a-f]{64})\.der")


def _leaf_seq(proof):
    try:
        leaf = load_json(proof.get("leaf_data"), "leaf", MAX_LINE)
        return leaf.get("seq") if isinstance(leaf, dict) and is_int(leaf.get("seq")) else None, leaf
    except (ValueError, TypeError, AttributeError):
        return None, None


def pack_invariants(manifest, files, records):
    """How a pack exported by PolicyGate is always built (the export's anchors part): [(seq|None, why)], one per
    difference. With --require-anchors each is a FAIL, otherwise a WARNING line. Structural only (no signatures, no
    TSA checks), so it runs with or without --tsa-roots.

    I1  anchoring.present false: no anchors/ file, in the pack or in the manifest.
    I2  anchoring.present true: the pack has records, and carries anchors/statements.jsonl and anchors/proofs.jsonl.
    I3  statements: anchor_seq ascending and contiguous, exactly first_anchor_seq..last_anchor_seq; as many as
        anchoring.anchors says.
    I4  proofs: at most one per anchor, in anchor order, each for a statement in the pack and of that statement's
        tree_size, each holding this tenant's leaf (the tenant hash the manifest names); as many as anchoring.proofs.
    I5  every statement has a proof for this tenant (every anchor after a tenant's first record holds its leaf). The
        one exception: a pack that no anchor covers carries just the latest anchor, and has no proof for it when the
        tenant had no records yet when it was made; then no record of the pack may predate that statement.
    I6  with more than one statement: the first one's head is at or after the pack's first seq (a pack starts at the
        first anchor that covers its first record), and every statement but the last has a head before the pack's
        last seq (it ends at the first anchor that covers its last record).
    I7  tokens: every statement has at least one; each entry names a statement in the pack and the file
        anchors/tokens/<anchor_seq>-<tsa>.tsr, present in the pack, used once, entries in anchor order; no token file
        outside the entries.
    I8  anchors/tsa-certs/<sha256>.der: the name is the file's SHA-256, and the files are the manifest's tsa_certs.
    I9  no other file under anchors/."""
    out = []
    info = manifest.get("anchoring") or {}
    declared = manifest.get("files") or {}
    names = sorted(set(n for n in files if n.startswith("anchors/")) | set(n for n in declared
                                                                         if n.startswith("anchors/")))
    if not info.get("present"):
        if names:
            out.append((None, "the manifest says the pack carries no anchors, yet it holds or declares %s%s"
                        % (", ".join(short_text(n, 60) for n in names[:3]), ", ..." if len(names) > 3 else "")))
        return out
    seq_range = manifest.get("seq_range")
    if not seq_range or not records:
        out.append((None, "anchors in a pack with no records (an empty window carries none)"))
        return out
    first, last = seq_range["first"], seq_range["last"]
    for name in ANCHOR_FILES:
        if name not in files:
            out.append((None, "%s is missing (every anchored pack carries it)" % name))
    try:
        statements = _jsonl(files.get("anchors/statements.jsonl", b""), "anchors/statements.jsonl")
        proofs = _jsonl(files.get("anchors/proofs.jsonl", b""), "anchors/proofs.jsonl")
    except ValueError:
        return out  # malformed: the anchor checks say so
    st_seqs = [x.get("anchor_seq") for x in statements]
    if not statements:
        out.append((None, "anchors/statements.jsonl holds no statement"))
        return out
    a0, a1 = info.get("first_anchor_seq"), info.get("last_anchor_seq")
    if not all(is_int(n) for n in st_seqs) or st_seqs != list(range(a0, a1 + 1)):
        out.append((None, "anchors/statements.jsonl holds anchors %s, not %s..%s in order, one each"
                    % (short_text(",".join(str(n) for n in st_seqs), 80), a0, a1)))
    if info.get("anchors") != len(statements):
        out.append((None, "anchors/statements.jsonl holds %d statement(s), the manifest says %s"
                    % (len(statements), info.get("anchors"))))
    st_info = {}
    for x in statements:
        try:
            st = load_json(x.get("statement"), "statement", MAX_LINE)
            st_info[x.get("anchor_seq")] = (st.get("tree_size"), parse_time(st.get("created_at")))
        except (ValueError, TypeError, AttributeError):
            pass

    tenant_sha = hashlib.sha256((TENANT_DOMAIN + manifest["tenant"]).encode("utf-8")).hexdigest()
    if info.get("tenant_sha256") != tenant_sha:
        out.append((None, "the manifest's anchoring.tenant_sha256 is not this tenant's"))
    pr_seqs = [x.get("anchor_seq") for x in proofs]
    for n in sorted(set(k for k in pr_seqs if pr_seqs.count(k) > 1), key=str):
        out.append((None, "anchors/proofs.jsonl holds %d proofs for anchor %s (one per anchor)" % (pr_seqs.count(n), n)))
    if all(is_int(n) for n in pr_seqs) and pr_seqs != sorted(pr_seqs):
        out.append((None, "anchors/proofs.jsonl is not in anchor order"))
    for n in sorted(set(k for k in pr_seqs if k not in st_seqs), key=str):
        out.append((None, "anchors/proofs.jsonl holds a proof for anchor %s, which has no statement in the pack" % n))
    if info.get("proofs") != len(proofs):
        out.append((None, "anchors/proofs.jsonl holds %d proof(s), the manifest says %s"
                    % (len(proofs), info.get("proofs"))))
    heads = {}
    for x in proofs:
        n = x.get("anchor_seq")
        h, leaf = _leaf_seq(x)
        if leaf is not None and leaf.get("tenant_sha256") != tenant_sha:
            out.append((None, "the proof for anchor %s holds another tenant's leaf" % n))
        if n in st_info and x.get("tree_size") != st_info[n][0]:
            out.append((None, "the proof for anchor %s is for a tree of %s leaves, its statement says %s"
                        % (n, x.get("tree_size"), st_info[n][0])))
        if h is not None:
            heads.setdefault(n, h)

    without = [n for n in st_seqs if n not in pr_seqs]
    if len(statements) == 1:
        n = st_seqs[0]
        made = st_info.get(n, (None, None))[1]
        if without and made is not None:
            for r in records:
                try:
                    t = record_time(r)
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                if t < made - MAX_SKEW:
                    out.append((r["seq"], "the pack has no proof for this tenant under its only anchor %s, which a "
                                          "PolicyGate pack has only when the tenant had no records yet when that "
                                          "anchor was made (%s), but seq %d was recorded at %s"
                                % (n, iso(made), r["seq"], iso(t))))
                    break
    else:
        if without:
            out.append((None,
                        "anchor(s) %s have no proof for this tenant: a pack with more than one anchor holds a proof "
                        "for each (every anchor after a tenant's first record holds its leaf)"
                        % short_text(", ".join(str(n) for n in without), 80)))
        h0 = heads.get(st_seqs[0])
        if h0 is not None and h0 < first:
            out.append((None, "the pack's first anchor %s saw seq %d, before the pack's first seq %d: a pack with "
                              "more than one anchor starts at the first anchor that covers its first record"
                        % (st_seqs[0], h0, first)))
        for n in st_seqs[:-1]:
            if heads.get(n) is not None and heads[n] >= last:
                out.append((None, "anchor %s already covers the pack's last seq %d, yet later anchors follow: a pack "
                                  "ends at the first anchor that covers its last record" % (n, last)))
                break

    tokens = info.get("tokens") or []
    used = []
    order = []
    for t in tokens:
        n, name, tsa = t.get("anchor_seq"), t.get("file"), t.get("tsa")
        order.append(n)
        m = TOKEN_NAME.fullmatch(name or "")
        if n not in st_seqs:
            out.append((None, "a token entry names anchor %s, which has no statement in the pack" % n))
        if not m or m.group(1) != str(n) or m.group(2) != tsa:
            out.append((None, "the token entry for anchor %s by %s points at %s, not anchors/tokens/%s-%s.tsr"
                        % (n, short_text(str(tsa), 40), short_text(str(name), 80), n, short_text(str(tsa), 40))))
        elif name not in files:
            out.append((None, "%s (the token of anchor %s) is missing from the pack" % (name, n)))
        if name in used:
            out.append((None, "two token entries point at %s" % short_text(str(name), 80)))
        used.append(name)
    if all(is_int(n) for n in order) and order != sorted(order):
        out.append((None, "the manifest's token entries are not in anchor order"))
    no_token = [n for n in st_seqs if n not in order]
    if no_token:
        out.append((None, "anchor(s) %s have no TSA token entry (every anchor is stored only once a TSA answered)"
                    % short_text(", ".join(str(n) for n in no_token), 80)))
    for name in names:
        if name.startswith("anchors/tokens/") and name not in used:
            out.append((None, "%s is not named by any token entry" % short_text(name, 80)))

    certs = [n for n in names if n.startswith("anchors/tsa-certs/")]
    for name in certs:
        m = CERT_NAME.fullmatch(name)
        if not m or (name in files and hashlib.sha256(files[name]).hexdigest() != m.group(1)):
            out.append((None, "%s is not named after its SHA-256" % short_text(name, 100)))
    listed = info.get("tsa_certs")
    if isinstance(listed, list) and sorted("anchors/tsa-certs/%s.der" % c for c in listed if isinstance(c, str)) \
            != sorted(certs):
        out.append((None, "the anchors/tsa-certs/ files are not the manifest's tsa_certs"))
    for name in names:
        if name not in ANCHOR_FILES and not name.startswith(("anchors/tokens/", "anchors/tsa-certs/")):
            out.append((None, "%s is not a file an anchored pack carries" % short_text(name, 100)))
    return out


def coverage_lines(manifest, segments, last_valid, bad_seqs=(), anchors=None):
    """bad_seqs: records that failed their own checks (hash, signature, chain); a range holding one is never printed
    as ANCHORED."""
    lines = []
    seq_range = manifest.get("seq_range")
    for a, b, anchor in segments:
        bad = sorted(s for s in bad_seqs if a <= s <= b)
        if bad:
            lines.append("ANCHOR CHECKED, RECORDS FAILED: seq %d..%d: anchor %s (%s at %s) verifies, but seq %s in "
                         "this range failed its own checks (see the FAIL lines), so the range is not proven"
                         % (a, b, anchor["anchor_seq"], anchor["tsa"], iso(anchor["gen_time"]),
                            ", ".join(str(s) for s in bad[:5]) + (", ..." if len(bad) > 5 else "")))
            continue
        lines.append("ANCHORED: seq %d..%d covered by %s at %s (anchor %s)"
                     % (a, b, anchor["tsa"], iso(anchor["gen_time"]), anchor["anchor_seq"]))
    if seq_range:
        covered = segments[-1][1] if segments else seq_range["first"] - 1
        for n in sorted(anchors or {}):
            if "beyond" in anchors[n] and covered < seq_range["last"]:
                lines.append("ANCHOR BEYOND THIS PACK: anchor %s saw seq %d, after this pack's last seq %d, so it "
                             "proves nothing about seq %d..%d here (export a pack that reaches seq %d to check them)"
                             % (n, anchors[n]["beyond"], seq_range["last"], covered + 1, seq_range["last"],
                                anchors[n]["beyond"]))
                break
        if covered < seq_range["last"]:
            after = ("after %s" % iso(last_valid["gen_time"])) if last_valid else \
                "no anchor in this pack verifies with a checked proof for this tenant"
            lines.append("NOT YET ANCHORED: seq %d..%d (%s)" % (covered + 1, seq_range["last"], after))
    return lines


def require_anchor_failures(records, segments, last_valid, since, grace, interval, present):
    """--require-anchors --anchored-since: [(seq, why)], empty when every record that must be covered is.

    A record must be covered when its signed created_at is at or after `since`. The grace rule: an uncovered record
    passes only if its signed created_at is before T + interval + grace, T being the genTime of the latest anchor in
    the pack that verifies with a checked proof for this tenant (last_valid, see verify_anchors; a TSA's time), or
    `since` when there is none or it is older. T never comes from the manifest or the records, so leaving anchors or
    proofs out only moves it earlier. Signed created_at may never be more than MAX_SKEW before the latest created_at
    of an earlier seq, so records cannot be re-dated backwards (not even a little per record) to before `since`. The
    failure names the first uncovered record recorded at or after `since`."""
    covered = segments[-1][1] if segments else 0
    if last_valid is not None and last_valid["gen_time"] > since:
        base, base_what = last_valid["gen_time"], "the latest valid anchor %s" % last_valid["anchor_seq"]
    else:
        base = since
        base_what = "--anchored-since (%s)" % (
            "the pack: it carries no anchors" if not present else
            "the pack: none of its anchors verifies with a checked proof for this tenant" if last_valid is None
            else "the pack's latest valid anchor is older")
    limit = base + interval + grace
    first_uncovered = None
    latest = None
    for r in records:
        try:
            t = record_time(r)
        except (ValueError, KeyError, TypeError, AttributeError):
            if r["seq"] > covered:
                return [(r["seq"], "seq %d is not covered by any anchor and its signed created_at is unreadable, so "
                                   "it cannot be shown to predate --anchored-since" % r["seq"])]
            continue
        if latest is not None and t < latest[1] - MAX_SKEW:
            return [(r["seq"], "seq %d: signed created_at %s is before seq %d's %s: records re-dated out of order"
                     % (r["seq"], iso(t), latest[0], iso(latest[1])))]
        if latest is None or t > latest[1]:
            latest = (r["seq"], t)
        if r["seq"] <= covered or t < since:
            continue
        if first_uncovered is None:
            first_uncovered = (r["seq"], t)
        if t >= limit:
            rule = ("only records recorded before %s (%s at %s + interval %s + grace %s) may wait for the next "
                    "anchor; anchoring runs since %s" % (iso(limit), base_what, iso(base), _span(interval),
                                                         _span(grace), iso(since)))
            if first_uncovered[0] == r["seq"]:
                return [(r["seq"], "seq %d (recorded at %s) and the records after it are not covered by any anchor: "
                                   "%s" % (r["seq"], iso(t), rule))]
            return [(first_uncovered[0], "seq %d (recorded at %s) and the records after it are not covered by any "
                                         "anchor, but seq %d was recorded at %s: %s"
                     % (first_uncovered[0], iso(first_uncovered[1]), r["seq"], iso(t), rule))]
    return []


def _span(d):
    s = int(d.total_seconds())
    return "%dm" % (s // 60) if s % 60 == 0 and s else "%ds" % s


def previous_pack_failures(manifest, records, previous, pin=None):
    """Compares the overlapping seq range with an older pack of the same tenant; returns [(seq, why)]."""
    failures, old_manifest, old_records = verify_pack_records(previous, pin)
    if failures:
        return [(None, "--previous-pack %s does not verify: %s" % (previous, failures[0]))], None
    if old_manifest.get("tenant") != manifest.get("tenant"):
        return [(None, "--previous-pack is for tenant %r, not %r" % (old_manifest.get("tenant"),
                                                                      manifest.get("tenant")))], None
    now = {r["seq"]: r for r in records}
    head = (manifest.get("chain_head") or {}).get("seq") or 0
    out = []
    overlap = 0
    for r in old_records:
        cur = now.get(r["seq"])
        if cur is not None:
            overlap += 1
            if cur["body_sha256"] != r["body_sha256"]:
                out.append((r["seq"], "differs from the previous pack (%s): record %s there, %s here" % (
                    os.path.basename(previous), r.get("id"), cur.get("id"))))
                break
        elif r["seq"] > head:
            out.append((head + 1, "the previous pack holds seq %d, the chain now ends at seq %d: records deleted"
                        % (r["seq"], head)))
            break
    return out, overlap


def first_bad(failures):
    """The failure naming the first bad seq. Exact ones are (seq, why); an anchor mismatch is (from, why, to): the
    first changed record is somewhere in from..to. An exact seq inside or before the earliest range wins."""
    exact = [f for f in failures if f[0] is not None and len(f) == 2]
    ranged = [f for f in failures if f[0] is not None and len(f) == 3]
    best = min(exact, key=lambda f: f[0]) if exact else None
    earliest = min(ranged, key=lambda f: (f[2], f[0])) if ranged else None
    if best is not None and (earliest is None or best[0] <= earliest[2]):
        return best
    return earliest


def print_failures(failures):
    """failures: [(seq|None, why[, upper])]. The first bad seq first, then every problem."""
    first = first_bad(failures)
    if first is not None:
        print("FAIL: first bad seq %d (%s)" % (first[0], first[1]), file=sys.stderr)
    for f in failures:
        print("FAIL: " + f[1], file=sys.stderr)


SEQ_PREFIX = re.compile(r"^seq (\d+)\b")


EXPECTED_SEQ = re.compile(r"expected seq (\d+)")


def with_seq(failure):
    """(seq the failure is about, text); a gap names the missing seq, not the record after it."""
    m = EXPECTED_SEQ.search(failure) or SEQ_PREFIX.match(failure)
    return (int(m.group(1)) if m else None, failure)


def decode_payment_signature(value):
    """x402 v2 PaymentPayload from the PAYMENT-SIGNATURE header value (standard or URL-safe base64)."""
    text = value.strip()
    raw = base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4), validate=True)
    payload = load_json(raw, "PAYMENT-SIGNATURE", MAX_LINE)
    if not isinstance(payload, dict) or payload.get("x402Version") != 2:
        raise ValueError("not an x402 v2 PaymentPayload")
    accepted, inner = payload.get("accepted"), payload.get("payload")
    if not isinstance(accepted, dict) or not isinstance(inner, dict):
        raise ValueError("PaymentPayload has no accepted / payload object")
    auth = inner.get("authorization")
    if not isinstance(auth, dict) or not isinstance(inner.get("signature"), str):
        raise ValueError("PaymentPayload.payload has no authorization / signature (exact/EVM, EIP-3009)")
    for field in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if not isinstance(auth.get(field), str):
            raise ValueError("authorization.%s missing" % field)
    for field in ("network", "asset"):
        if not isinstance(accepted.get(field), str):
            raise ValueError("accepted.%s missing" % field)
    return payload


def match_payment(records, value):
    """(matched, seq, message): the payment.sign record covering the PAYMENT-SIGNATURE value, or why there is none."""
    payload = decode_payment_signature(value)
    accepted, auth = payload["accepted"], payload["payload"]["authorization"]
    network = accepted["network"].lower() if accepted["network"].lower().startswith("eip155:") else accepted["network"]
    wanted = authorization_sha256(network, accepted["asset"], auth["from"], auth["to"], auth["value"], auth["nonce"],
                                  auth["validAfter"], auth["validBefore"])
    for record in records:
        body = load_json(record["canonical"], "record", MAX_LINE)
        p = body.get("payload") if isinstance(body, dict) else None
        if body.get("decision_type") != "agent_spend" or not isinstance(p, dict) or p.get("event") != "payment.sign" \
                or p.get("authorization_sha256") != wanted:
            continue
        where = "record %s seq %s" % (record.get("id"), record.get("seq"))
        authorization = {"from": auth["from"], "to": auth["to"], "value": auth["value"],
                         "valid_after": auth["validAfter"], "valid_before": auth["validBefore"], "nonce": auth["nonce"]}
        digest = eip712_digest(p["eip712"]["domain"], authorization)
        if "0x" + digest.hex() != p["eip712"].get("digest"):
            return False, None, "%s signed this authorization hash, but under another EIP-712 digest" % where
        try:
            signature = bytes.fromhex(payload["payload"]["signature"][2:]
                                      if payload["payload"]["signature"].startswith("0x")
                                      else payload["payload"]["signature"])
        except ValueError:
            return False, None, "the payload's signature is not hex"
        point = recover_public_key(digest, signature)
        if point is None or not cryptography_verifies(point, digest, signature):
            return False, None, "the payload's signature is not a valid secp256k1 signature of the EIP-712 digest"
        recovered = eth_address(point)
        if recovered != str(p.get("payer")).lower():
            return False, None, ("%s covers this authorization for payer %s, but the signature recovers %s"
                           % (where, p.get("payer"), recovered))
        return True, record["seq"], ("MATCH: %s tenant=%s agent=%s payment_id=%s amount_units=%s asset=%s "
                                     "pay_to=%s payer=%s "
                      "authorization_sha256=%s decided_at=%s"
                      % (where, body.get("tenant_id"), body.get("subject"), p.get("payment_id"),
                         p.get("amount_units"), p.get("asset_id"), p.get("pay_to"), recovered, wanted,
                         body.get("created_at")))
    return False, None, "no payment.sign record in this pack has authorization_sha256 %s" % wanted


def kids_used(manifest, records, files):
    """The kids a pack's manifest, records and anchor statements name, in order of first use."""
    kids = [manifest.get("signing_kid")] + [r.get("kid") for r in records]
    try:
        kids += [s.get("kid") for s in _jsonl(files.get("anchors/statements.jsonl", b""), "statements")]
    except ValueError:
        pass
    out = []
    for kid in kids:
        if isinstance(kid, str) and kid not in out:
            out.append(kid)
    return out


def key_not_pinned_line(kids):
    if len(kids) == 1:
        used = "the key inside this pack (kid %s)" % kids[0]
    else:
        used = "the keys inside this pack (kids %s)" % ", ".join(kids)
    return ("KEY NOT PINNED: verified against %s. Compare it with the signer's published key, or pass "
            "--expect-kid." % used)


def offline(args, roots):
    """Verifies the pack (and its anchors, with roots). Returns (failures [(seq, why)], manifest, records, lines,
    segments, last_valid, kids)."""
    failures, manifest, records, files = verify_pack_files(args.input, args.pin)
    fails = [with_seq(f) for f in failures]
    lines, segments, last_valid = [], [], None
    if manifest is None:
        return fails, manifest, records, lines, segments, last_valid, []
    kids = kids_used(manifest, records, files)
    bad_seqs = {seq for seq, _ in fails if seq is not None}
    info = manifest.get("anchoring") or {}
    try:
        broken = pack_invariants(manifest, files, records)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        broken = [(None, "cannot check (%s)" % short_text(e))]
    if args.require_anchors:
        fails += [(seq, "pack invariant broken: %s" % why) for seq, why in broken]
    else:
        lines += ["WARNING: pack invariant broken: %s (a pack exported by PolicyGate never looks like this; "
                  "--require-anchors fails on it)" % why for _, why in broken]
    if info.get("present"):
        if roots is not None:
            try:
                keys = load_keys(load_json(files["jwks.json"], "jwks.json", MAX_LINE))
                anchor_fails, segments, anchors, last_valid = verify_anchors(manifest, files, records, keys, roots)
                fails += anchor_fails
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                anchors = {}
                fails.append((None, "anchors: %s" % short_text(e)))
            lines = coverage_lines(manifest, segments, last_valid, bad_seqs, anchors) + lines
        else:
            lines.append("ANCHORS NOT CHECKED: this pack carries anchors %s..%s; pass --tsa-roots <your pinned "
                         "roots> to check them" % (info.get("first_anchor_seq"), info.get("last_anchor_seq")))
    elif manifest.get("seq_range"):
        lines.append("NOT ANCHORED: this pack carries no anchors")
    if args.require_anchors:
        try:
            fails += require_anchor_failures(records, segments, last_valid, args.anchored_since,
                                             args.anchor_grace, args.anchor_interval, bool(info.get("present")))
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            fails.append((None, "--require-anchors: %s" % short_text(e)))
    if args.previous_pack:
        previous, overlap = previous_pack_failures(manifest, records, args.previous_pack, args.pin)
        fails += previous
        if not previous:
            lines.append("PREVIOUS PACK: the %d record(s) both packs hold are identical" % overlap)
    return fails, manifest, records, lines, segments, last_valid, kids


def anchor_status(seq, manifest, segments, last_valid, roots):
    if not (manifest.get("anchoring") or {}).get("present"):
        return "NOT ANCHORED: seq %d (this pack carries no anchors)" % seq
    if roots is None:
        return "ANCHOR STATUS: not checked (pass --tsa-roots)"
    for a, b, anchor in segments:
        if a <= seq <= b:
            return "ANCHORED: seq %d covered by %s at %s (anchor %s)" % (
                seq, anchor["tsa"], iso(anchor["gen_time"]), anchor["anchor_seq"])
    after = ("after %s" % iso(last_valid["gen_time"])) if last_valid else "no valid anchor in this pack"
    return ("NOT YET ANCHORED: seq %d (%s). The next anchor follows within the anchoring interval (10 min by "
            "default); export a new pack after it and match again." % (seq, after))


def main_match(args, roots, value):
    fails, manifest, records, lines, segments, last_valid, kids = offline(args, roots)
    if fails:
        print_failures(fails)
        print("FAIL: %d problem(s) in %s; not matching against an invalid pack" % (len(fails), args.input),
              file=sys.stderr)
        return 1
    try:
        matched, seq, message = match_payment(records, value)
    except (ValueError, UnicodeDecodeError, OverflowError) as e:
        print("FAIL: --match-payment: %s" % short_text(e), file=sys.stderr)
        return 2
    if matched:
        print(message)
        print(anchor_status(seq, manifest, segments, last_valid, roots))
    else:
        print("NO MATCH: %s. No policy decision in this pack (tenant=%s, %s..%s) covers this payment."
              % (message, manifest.get("tenant"), (manifest.get("window") or {}).get("from"),
                 (manifest.get("window") or {}).get("to")))
    if args.pin is None:
        print(key_not_pinned_line(kids))
    return 0 if matched else 1


def main_offline(args, roots):
    fails, manifest, records, lines, _, _, kids = offline(args, roots)
    for line in lines:
        print(line)
    if fails:
        print_failures(fails)
        print("FAIL: %d problem(s) in %s" % (len(fails), args.input), file=sys.stderr)
        return 1
    seq_range = manifest.get("seq_range")
    span = "%d..%d" % (seq_range["first"], seq_range["last"]) if seq_range else "none (empty window)"
    head = manifest.get("chain_head") or {}
    print("OK: pack=%s tenant=%s records=%d seq=%s anchor=%s head_seq=%s export_id=%s"
          % (args.input, manifest.get("tenant"), manifest.get("record_count"), span, manifest.get("anchor"),
             head.get("seq"), short_text(manifest.get("export_id"))))
    if args.pin is None:
        print(key_not_pinned_line(kids))
    return 0


def read_token_default():
    return os.environ.get("POLICYGATE_EVIDENCE_READ_TOKEN")


def _join_option_values(argv, options):
    """["--expect-kid", "-x..."] -> ["--expect-kid=-x..."]: a key id may start with "-", which argparse would
    otherwise take for an option."""
    out = []
    i = 0
    while i < len(argv):
        if argv[i] == "--":
            out += argv[i:]
            break
        if argv[i] in options and i + 1 < len(argv):
            out.append("%s=%s" % (argv[i], argv[i + 1]))
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("--input", help="offline: an export pack (.zip) or the directory it was unpacked into")
    parser.add_argument("--expect-kid", metavar="KID", action="append",
                        help="the signer's key id (RFC 7638 thumbprint) you trust; repeat for each key (e.g. across "
                             "a key rotation). The manifest, every record and every anchor statement must be signed "
                             "by one of them")
    parser.add_argument("--keys-file", metavar="FILE",
                        help="the signer's public keys as a JWKS obtained out of band; every key the pack (or the "
                             "chain) uses must be one of them")
    parser.add_argument("--match-payment", metavar="PAYMENT_SIGNATURE",
                        help="with --input: the base64 x402 PAYMENT-SIGNATURE value to match to a payment.sign record; "
                             "@FILE reads it from FILE, - from stdin (keeps it off the command line)")
    parser.add_argument("--base-url",
                        help="online: base URL of the PolicyGate deployment, e.g. https://policygate.example")
    parser.add_argument("--tenant", help="online: the tenant whose chain is verified")
    parser.add_argument("--from-seq", type=int, default=1, help="online: first seq to verify (default 1)")
    parser.add_argument("--expect-prev-hash",
                        help="online: body_sha256 of seq (from-seq - 1); anchors a partial verification")
    parser.add_argument("--token", default=read_token_default(),
                        help="online: read token (default: $POLICYGATE_EVIDENCE_READ_TOKEN)")
    parser.add_argument("--tsa-roots", metavar="FILE",
                        help="with --input: YOUR pinned TSA roots (format pg.tsa-roots.v1); checks the pack's anchors")
    parser.add_argument("--require-anchors", action="store_true",
                        help="with --input and --tsa-roots (audit mode): every record whose signed created_at is "
                             "at or after --anchored-since must be covered by an anchor, except the newest records "
                             "waiting for the next one")
    parser.add_argument("--anchored-since", metavar="DATE",
                        help="with --require-anchors: when the signer started anchoring (RFC 3339 with a time "
                             "zone), from the organisation that runs PolicyGate through a separate channel, never "
                             "from the pack")
    parser.add_argument("--anchor-grace", default="15m",
                        help="with --require-anchors: extra time the newest records may wait for an anchor, on "
                             "top of --anchor-interval (default 15m)")
    parser.add_argument("--anchor-interval", default="10m",
                        help="with --require-anchors: the signer's anchoring interval (default 10m); uncovered "
                             "records must be recorded before the latest valid anchor's genTime + interval + grace "
                             "(a valid anchor: it verifies and its proof for this tenant was checked). Only you set "
                             "these two; nothing in the pack does")
    parser.add_argument("--previous-pack", metavar="OLD",
                        help="with --input: an older pack of the same tenant; names the first record that changed")
    args = parser.parse_args(_join_option_values(sys.argv[1:] if argv is None else list(argv), ("--expect-kid",)))
    try:
        return run(args)
    except Exception as e:  # last resort: hostile input ends in a FAIL line, never a traceback
        what = "malformed pack" if args.input else "malformed response"
        print("FAIL: %s (%s: %s)" % (what, type(e).__name__, short_text(e, 120)), file=sys.stderr)
        return 1


def run(args):
    roots = None
    args.pin = None
    if args.tsa_roots or args.require_anchors or args.anchored_since or args.previous_pack:
        if not args.input:
            print("FAIL: --tsa-roots / --require-anchors / --previous-pack need --input <pack>", file=sys.stderr)
            return 2
    if args.anchored_since and not args.require_anchors:
        print("FAIL: --anchored-since only applies with --require-anchors (pass both, or neither)", file=sys.stderr)
        return 2
    if args.require_anchors and not (args.tsa_roots and args.anchored_since):
        print("FAIL: --require-anchors needs --tsa-roots and --anchored-since", file=sys.stderr)
        return 2
    for kid in args.expect_kid or []:
        if not KID_FORMAT.fullmatch(kid):
            print("FAIL: --expect-kid %r is not an Ed25519 key id (an RFC 7638 thumbprint: 43 base64url characters)"
                  % short_text(kid), file=sys.stderr)
            return 2
    try:
        pinned_keys = load_keys_file(args.keys_file) if args.keys_file else None
    except (OSError, ValueError) as e:
        print("FAIL: --keys-file: %s" % short_text(e, 300), file=sys.stderr)
        return 2
    if args.expect_kid or pinned_keys is not None:
        args.pin = KeyPin(args.expect_kid, pinned_keys, args.keys_file)
    try:
        if args.tsa_roots:
            roots = load_tsa_roots(args.tsa_roots)
        args.anchored_since = parse_time(args.anchored_since) if args.anchored_since else None
        args.anchor_grace = parse_duration(args.anchor_grace)
        args.anchor_interval = parse_duration(args.anchor_interval)
    except (OSError, ValueError) as e:
        print("FAIL: %s" % e, file=sys.stderr)
        return 2

    if args.input:
        if args.base_url or args.tenant:
            print("FAIL: --input is offline; do not combine it with --base-url / --tenant", file=sys.stderr)
            return 2
        if args.match_payment is not None:
            value = args.match_payment
            try:
                if value == "-":
                    value = sys.stdin.read()
                elif value.startswith("@"):
                    with open(value[1:]) as f:
                        value = f.read()
            except (OSError, UnicodeDecodeError) as e:
                print("FAIL: --match-payment: %s" % short_text(e), file=sys.stderr)
                return 2
            return main_match(args, roots, value)
        return main_offline(args, roots)
    if args.match_payment is not None:
        print("FAIL: --match-payment needs --input <pack>", file=sys.stderr)
        return 2
    if not args.base_url or not args.tenant:
        print("FAIL: pass --input <pack>, or --base-url and --tenant", file=sys.stderr)
        return 2
    if not args.token:
        print("FAIL: no read token (set POLICYGATE_EVIDENCE_READ_TOKEN or pass --token)", file=sys.stderr)
        return 2
    if args.from_seq < 1:
        print("FAIL: --from-seq must be >= 1", file=sys.stderr)
        return 2
    base_url = args.base_url.rstrip("/")

    try:
        keys = load_keys(http_get_json(base_url + "/v1/evidence/keys"))
        records = fetch_chain(base_url, args.tenant, args.from_seq, args.token)
    except urllib.error.HTTPError as e:
        print("FAIL: HTTP %d from %s" % (e.code, e.url), file=sys.stderr)
        return 1
    except (urllib.error.URLError, ValueError, KeyError, TypeError) as e:
        print("FAIL: %s" % short_text(e, 300), file=sys.stderr)
        return 1

    failures = verify_chain(records, keys, args.tenant, args.from_seq, args.expect_prev_hash, pin=args.pin)
    if failures:
        for failure in failures:
            print("FAIL: " + failure, file=sys.stderr)
        print("FAIL: %d problem(s) in %d record(s)" % (len(failures), len(records)), file=sys.stderr)
        return 1

    anchor = "genesis" if args.from_seq == 1 else ("--expect-prev-hash" if args.expect_prev_hash else "UNANCHORED")
    print("OK: tenant=%s records=%d seq=%d..%d head=%s anchor=%s"
          % (args.tenant, len(records), records[0]["seq"], records[-1]["seq"], records[-1]["body_sha256"], anchor))
    return 0


if __name__ == "__main__":
    sys.exit(main())
