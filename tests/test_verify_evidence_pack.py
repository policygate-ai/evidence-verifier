"""verify-evidence.py end to end on packs built here (evidence_testpack.py, throwaway keys): no Docker, no network
beyond 127.0.0.1. Each case runs the script as a user would (python3 -I verify-evidence.py ...) and checks its exit
code and output: a clean pack, tampering, key pinning (--expect-kid / --keys-file), duplicate zip entries, malformed
packs, which must end in a FAIL line, never a traceback, and the audit mode (--require-anchors --anchored-since)
against packs forged with the signing key. Key ids are passed as --expect-kid=KID: a random one may start with "-"."""
import contextlib
import datetime
import hashlib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "verify-evidence.py")
sys.path.insert(0, HERE)
import evidence_testpack as tp  # noqa: E402

_spec = importlib.util.spec_from_file_location("verify_evidence_pack_tests", SCRIPT)
ve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ve)

TENANT = "demo"

try:
    import asn1crypto  # noqa: F401
    HAVE_ASN1 = True
except ImportError:
    HAVE_ASN1 = False


# -I ignores PYTHONPATH: when the pinned asn1crypto is found through PYTHONPATH, hand those directories to the
# isolated interpreter explicitly, then run the script as __main__ (python3 -I verify-evidence.py ... otherwise).
EXTRA_PATH = [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]
BOOT = (["-c", "import runpy, sys; sys.path[:0] = %r; sys.argv = sys.argv[1:]; "
               "runpy.run_path(sys.argv[0], run_name='__main__')" % [os.path.abspath(p) for p in EXTRA_PATH]]
        if EXTRA_PATH else [])


def run(*args, env=None, stdin=None):
    """(exit code, stdout, stderr) of the script; the environment holds no proxy and no read token unless given."""
    base = {k: v for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
            and not k.endswith("EVIDENCE_READ_TOKEN")}
    base.update(env or {})
    p = subprocess.run([sys.executable, "-I"] + BOOT + [SCRIPT] + [str(a) for a in args], capture_output=True,
                       text=True, env=base, input=stdin, timeout=120)
    return p.returncode, p.stdout, p.stderr


class PackCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.signer = tp.Signer()
        self.records = tp.chain(self.signer, TENANT, 3)

    def zip(self, files, name="pack.zip", duplicates=()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # zipfile warns about the duplicate names a test asks for
            return tp.write_zip(os.path.join(self.dir, name), files, duplicates)

    def pack(self, records=None, name="pack.zip", **kw):
        return self.zip(tp.pack_files(self.records if records is None else records, self.signer, TENANT, **kw),
                        name)

    def assertOk(self, result):
        code, out, err = result
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("Traceback", err)
        self.assertIn("OK: pack=", out)
        return out

    def assertFail(self, result, *needles, first_bad_seq=None):
        code, out, err = result
        self.assertEqual(code, 1, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertNotIn("OK: pack=", out)
        self.assertTrue(err.startswith("FAIL: "), err)
        for needle in needles:
            self.assertIn(needle, err)
        if first_bad_seq is not None:
            self.assertTrue(err.startswith("FAIL: first bad seq %d (" % first_bad_seq), err)
        return err


class Clean(PackCase):
    def test_clean_pack_verifies_and_says_the_key_is_not_pinned(self):
        out = self.assertOk(run("--input", self.pack()))
        lines = out.splitlines()
        self.assertTrue(lines[-2].startswith("OK: pack="), out)
        self.assertEqual(lines[-1], "KEY NOT PINNED: verified against the key inside this pack (kid %s). Compare "
                                    "it with the signer's published key, or pass --expect-kid." % self.signer.kid)
        self.assertIn("records=3 seq=1..3", out)

    def test_unpacked_directory_verifies(self):
        path = tp.write_dir(os.path.join(self.dir, "unpacked"), tp.pack_files(self.records, self.signer, TENANT))
        self.assertOk(run("--input", path))

    def test_pinned_by_kid_or_keys_file_prints_no_warning(self):
        path = self.pack()
        out = self.assertOk(run("--input", path, "--expect-kid=" + self.signer.kid))
        self.assertNotIn("KEY NOT PINNED", out)
        keys = os.path.join(self.dir, "signer-keys.json")
        with open(keys, "w") as f:
            json.dump({"keys": [self.signer.jwk()]}, f)
        out = self.assertOk(run("--input", path, "--keys-file", keys))
        self.assertNotIn("KEY NOT PINNED", out)
        other = tp.Signer()
        self.assertOk(run("--input", path, "--expect-kid=" + other.kid, "--expect-kid=" + self.signer.kid))

    def test_empty_pack_verifies(self):
        self.assertOk(run("--input", self.pack(records=[])))


class Tampering(PackCase):
    def test_altered_record_fails_at_its_seq(self):
        records = [dict(r) for r in self.records]
        records[1]["canonical"] = records[1]["canonical"].replace('"outcome":"allow"', '"outcome":"deny"')
        self.assertFail(run("--input", self.pack(records)), "signature INVALID", "sha256(canonical)",
                        first_bad_seq=2)

    def test_removed_middle_record_fails_as_a_gap(self):
        records = [self.records[0], self.records[2]]
        self.assertFail(run("--input", self.pack(records, edit=lambda m: m.update(seq_range={"first": 1, "last": 3}))),
                        "expected seq 2 (gap or reorder)", first_bad_seq=2)

    def test_removed_last_record_fails_against_the_manifest(self):
        files = tp.pack_files(self.records, self.signer, TENANT)
        files["records.jsonl"] = tp.jsonl(self.records[:2])  # the manifest still says 1..3
        self.assertFail(run("--input", self.zip(files)), "records missing at the end",
                        "records.jsonl: sha256", "record_count 3")

    def test_removed_last_record_with_a_resigned_manifest_needs_the_pin(self):
        forger = tp.Signer()
        path = self.pack(self.records[:2], jwks_signers=[self.signer, forger], manifest_signer=forger)
        out = self.assertOk(run("--input", path))  # consistent on its own: only the pin can tell
        self.assertIn("KEY NOT PINNED: verified against the keys inside this pack (kids %s, %s)"
                      % (forger.kid, self.signer.kid), out)
        self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid),
                        "the manifest is not signed by a pinned key: kid %r is not one of --expect-kid" % forger.kid)

    def test_two_records_swapped_fail_at_the_first_out_of_place(self):
        records = [self.records[0], self.records[2], self.records[1]]
        self.assertFail(run("--input", self.pack(records, edit=lambda m: m.update(
            seq_range={"first": 1, "last": 3}, chain_head={"seq": 3, "hash": self.records[2]["body_sha256"]}))),
            "expected seq 2 (gap or reorder)", first_bad_seq=2)

    def test_chain_head_edited_alone(self):
        def edit(m):
            m["chain_head"]["hash"] = "ab" * 32
        self.assertFail(run("--input", self.pack(edit=edit)), "body_sha256 is not the manifest's chain_head hash",
                        first_bad_seq=3)
        files = tp.pack_files(self.records, self.signer, TENANT)
        manifest = json.loads(files["manifest.json"])
        manifest["chain_head"]["hash"] = "ab" * 32
        files["manifest.json"] = tp.canonical(manifest).encode("utf-8")  # not re-signed
        self.assertFail(run("--input", self.zip(files)), "manifest.sig: signature INVALID over manifest.json")

    def test_record_signed_by_a_key_missing_from_jwks(self):
        other = tp.Signer()
        records = list(self.records)
        records[1] = tp.resign(records[1], other)
        self.assertFail(run("--input", self.pack(records)), "unknown kid %r" % other.kid, first_bad_seq=2)

    def test_kid_that_is_not_the_thumbprint(self):
        jwk = dict(self.signer.jwk(), kid="A" * 43)
        jwks = json.dumps({"keys": [jwk]}).encode("utf-8")
        self.assertFail(run("--input", self.pack(jwks_bytes=jwks)), "is not the RFC 7638 thumbprint")

    def test_jwks_replaced_and_everything_resigned(self):
        forger = tp.Signer()
        records = tp.chain(forger, TENANT, 3)
        path = self.zip(tp.pack_files(records, forger, TENANT))
        out = self.assertOk(run("--input", path))
        self.assertIn("KEY NOT PINNED: verified against the key inside this pack (kid %s)" % forger.kid, out)
        self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid),
                        "kid %r is not one of --expect-kid" % forger.kid)
        keys = os.path.join(self.dir, "signer-keys.json")
        with open(keys, "w") as f:
            json.dump({"keys": [self.signer.jwk()]}, f)
        self.assertFail(run("--input", path, "--keys-file", keys), "kid %r is not in --keys-file" % forger.kid)

    def test_records_signed_by_an_unpinned_key_under_a_pinned_manifest(self):
        other = tp.Signer()
        records = [self.records[0], tp.resign(self.records[1], other), self.records[2]]
        path = self.pack(records, jwks_signers=[self.signer, other])
        self.assertOk(run("--input", path))
        self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid),
                        "seq 2 (id %s): not signed by a pinned key: kid %r is not one of --expect-kid"
                        % (records[1]["id"], other.kid), first_bad_seq=2)

    def test_anchor_statement_signed_by_an_unpinned_key(self):
        other = tp.Signer()
        statements = tp.jsonl([anchor_line(1, other)])
        path = self.pack(jwks_signers=[self.signer, other], extra_files={"anchors/statements.jsonl": statements},
                         edit=anchoring(1))
        self.assertOk(run("--input", path))
        self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid),
                        "anchors/statements.jsonl line 1: statement not signed by a pinned key: kid %r" % other.kid)

    def test_previous_pack_is_held_to_the_pin_too(self):
        forger = tp.Signer()
        old = self.zip(tp.pack_files(tp.chain(forger, TENANT, 3), forger, TENANT), name="old.zip")
        self.assertFail(run("--input", self.pack(), "--expect-kid=" + self.signer.kid, "--previous-pack", old),
                        "--previous-pack %s does not verify" % old)

    def test_duplicate_zip_entries_are_rejected(self):
        files = tp.pack_files(self.records, self.signer, TENANT)
        path = self.zip(files, duplicates=[("records.jsonl", tp.jsonl(self.records[:1]))])
        self.assertFail(run("--input", path), "REJECTED: ", "duplicate entry name 'records.jsonl'")


def anchor_line(n, signer, **statement_edits):
    st = {"anchor_seq": n, "created_at": "2026-11-07T12:10:00.000Z", "kid": signer.kid, "merkle_root": "cd" * 32,
          "prev_statement_sha256": tp.GENESIS, "schema": "pg.anchor.v1", "tree_size": 16}
    st.update(statement_edits)
    text = tp.canonical(st)
    return {"anchor_seq": n, "statement": text, "statement_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "statement_signature": signer.sign(text.encode()), "kid": signer.kid}


def anchoring(last):
    def edit(m):
        m["anchoring"] = {"present": True, "tenant_sha256": "00" * 32, "first_anchor_seq": 1,
                          "last_anchor_seq": last, "anchors": last, "proofs": 1, "tokens": [], "tsa_certs": []}
    return edit


def proof_line(**edits):
    leaf = tp.canonical({"head_hash": "ef" * 32, "seq": 3, "tenant_sha256": "00" * 32, "v": 1})
    line = {"anchor_seq": 1, "leaf_index": 0, "tree_size": 16, "leaf_data": leaf, "path": ["aa" * 32] * 4}
    line.update(edits)
    return line


class Malformed(PackCase):
    """Wrong types anywhere end in FAIL lines and exit 1, never a traceback."""

    MANIFEST_EDITS = [
        ("seq_range", "1..3"), ("seq_range", [1, 3]), ("seq_range", {"first": "1", "last": 3}),
        ("seq_range", {"first": True, "last": 3}), ("seq_range", {"first": 1}),
        ("anchoring", []), ("anchoring", "yes"), ("anchoring", {"present": "yes"}),
        ("anchoring", {"present": True, "first_anchor_seq": 1, "last_anchor_seq": 1, "tokens": "x"}),
        ("anchoring", {"present": True, "first_anchor_seq": "1", "last_anchor_seq": 1, "tokens": []}),
        ("anchoring", {"present": True, "first_anchor_seq": 1, "last_anchor_seq": 1, "tokens": [5]}),
        ("anchoring", {"present": True, "first_anchor_seq": 1, "last_anchor_seq": 1,
                       "tokens": [{"anchor_seq": 1, "file": ["x"], "tsa": "t"}]}),
        ("files", []), ("files", "x"), ("files", {"records.jsonl": "abc", "jwks.json": {"sha256": "x"}}),
        ("files", {"records.jsonl": {"sha256": 5}}),
        ("chain_head", [3, "h"]), ("chain_head", "x"), ("chain_head", {"seq": "3", "hash": "h"}),
        ("chain_head", {"seq": 3, "hash": 5}),
        ("record_count", "3"), ("record_count", None), ("anchor", 5), ("anchor", ["x"]),
        ("tenant", ["demo"]), ("tenant", 5), ("tenant", ""), ("window", "today"), ("window", {"from": 5}),
        ("created_at", 5), ("format", 1), ("format", ["pg.evidence.export.v1"]),
    ]

    def test_wrong_types_in_the_manifest(self):
        for field, value in self.MANIFEST_EDITS:
            with self.subTest(field=field, value=value):
                path = self.pack(edit=lambda m, f=field, v=value: m.__setitem__(f, v))
                self.assertFail(run("--input", path))
                self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid, "--match-payment",
                                    "e30="))

    def test_wrong_types_also_under_require_anchors_and_previous_pack(self):
        roots = self.roots()
        for field, value in (("created_at", 5), ("anchoring", {"present": True}), ("seq_range", "x")):
            with self.subTest(field=field):
                path = self.pack(edit=lambda m, f=field, v=value: m.__setitem__(f, v))
                self.assertFail(run("--input", path, "--tsa-roots", roots, "--require-anchors",
                                    "--anchored-since", "2026-01-01T00:00:00Z"))
                self.assertFail(run("--input", self.pack(name="good.zip"), "--previous-pack", path),
                                "--previous-pack")

    def test_signing_kid_of_the_wrong_type(self):
        for value in (["k"], 5, None, {"kid": "k"}):
            with self.subTest(value=value):
                files = tp.pack_files(self.records, self.signer, TENANT)
                manifest = json.loads(files["manifest.json"])
                manifest["signing_kid"] = value
                files["manifest.json"] = tp.canonical(manifest).encode("utf-8")
                files["manifest.sig"] = (self.signer.sign(files["manifest.json"]) + "\n").encode("ascii")
                self.assertFail(run("--input", self.zip(files)), "signing_kid")

    def test_manifest_or_jwks_of_the_wrong_shape(self):
        for name, data in (("manifest.json", b"[1, 2]"), ("manifest.json", b'"x"'), ("jwks.json", b"[]"),
                           ("jwks.json", b'{"keys": 5}'), ("jwks.json", b'{"keys": [5]}'),
                           ("jwks.json", b'{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": 5}]}'),
                           ("manifest.sig", b"\xff\xfe"), ("records.jsonl", b"\xff\xfe\n")):
            with self.subTest(name=name, data=data):
                files = tp.pack_files(self.records, self.signer, TENANT)
                files[name] = data
                self.assertFail(run("--input", self.zip(files)))

    def test_canonical_that_is_not_a_string_or_not_an_object(self):
        for text in ("[1]", '"text"', "5", "null"):
            with self.subTest(canonical=text):
                records = list(self.records)
                records[1] = tp.resign(records[1], self.signer, text)  # validly signed, hashes match
                records[2] = dict(records[2], prev_hash=records[1]["body_sha256"])
                self.assertFail(run("--input", self.pack(records)), "canonical is", first_bad_seq=2)
        for value in (5, ["x"], {"a": 1}, None, True):
            with self.subTest(canonical=value):
                records = list(self.records)
                records[1] = dict(records[1], canonical=value)
                self.assertFail(run("--input", self.pack(records)), "canonical is")

    def test_wrong_types_in_record_lines(self):
        for field, value in (("seq", "2"), ("seq", True), ("seq", 2.5), ("id", 5), ("kid", ["x"]), ("kid", None),
                             ("signature", 5), ("body_sha256", None), ("prev_hash", 7)):
            with self.subTest(field=field, value=value):
                records = list(self.records)
                records[1] = dict(records[1], **{field: value})
                self.assertFail(run("--input", self.pack(records)), "not a valid record")
        for line in (b"[1, 2]\n", b'"record"\n', b"5\n", b"{\n", b"[" * 100 + b"]" * 100 + b"\n"):
            with self.subTest(line=line[:20]):
                data = tp.jsonl(self.records[:1]) + line + tp.jsonl(self.records[1:])
                self.assertFail(run("--input", self.pack(records_bytes=data)), "records.jsonl line 2")

    def test_payment_record_with_values_out_of_range(self):
        payload = {"event": "payment.sign", "network": "eip155:31337", "asset_id": "eip155:31337/erc20:0x" + "11" * 20,
                   "payer": "0x" + "22" * 20, "pay_to": "eip155:31337:0x" + "33" * 20, "amount_units": "-1",
                   "authorization_sha256": "x", "signer": {"payer": "0x" + "22" * 20},
                   "authorization": {"from": "0x" + "22" * 20, "to": "0x" + "33" * 20, "value": "-1",
                                     "valid_after": "0", "valid_before": "99", "nonce": "0x" + "00" * 32},
                   "eip712": {"domain": {"name": "T", "version": "2", "chain_id": "31337",
                                         "verifying_contract": "0x" + "11" * 20}, "digest": "0x00"}}
        for edit in ({}, {"eip712": "x"}, {"authorization": [1]}, {"signer": 5}):
            with self.subTest(edit=edit):
                records = tp.chain(self.signer, TENANT, 2, bodies={2: {"decision_type": "agent_spend",
                                                                       "payload": dict(payload, **edit)}})
                self.assertFail(run("--input", self.pack(records)), "payment", first_bad_seq=2)

    def roots(self):
        path = os.path.join(self.dir, "tsa-roots.json")
        with open(path, "w") as f:
            json.dump({"format": "pg.tsa-roots.v1", "roots": [{"name": "t", "spki_sha256": "00" * 32,
                                                                "policy_oids": ["1.2.3"]}]}, f)
        return path

    def anchored(self, statements, proofs):
        return self.pack(extra_files={"anchors/statements.jsonl": statements, "anchors/proofs.jsonl": proofs},
                         edit=anchoring(1))

    def test_wrong_types_in_statements_and_proofs(self):
        roots = self.roots()
        good_statement = tp.jsonl([anchor_line(1, self.signer)])
        good_proof = tp.jsonl([proof_line()])
        statements = [
            tp.jsonl([dict(anchor_line(1, self.signer), anchor_seq="1")]),
            tp.jsonl([dict(anchor_line(1, self.signer), statement=5)]),
            tp.jsonl([dict(anchor_line(1, self.signer), kid=["k"])]),
            tp.jsonl([dict(anchor_line(1, self.signer), statement_signature=None)]),
            tp.jsonl([dict(anchor_line(1, self.signer), statement_sha256=7)]),
            tp.jsonl([dict(anchor_line(1, self.signer), statement="[1]")]),
            tp.jsonl([anchor_line(1, self.signer, tree_size="16")]),
            tp.jsonl([anchor_line(1, self.signer, merkle_root=5)]),
            tp.jsonl([anchor_line(1, self.signer, created_at=5)]),
            tp.jsonl([anchor_line(1, self.signer, anchor_seq=[1])]),
            b"[1]\n", b"5\n", b"{\n", b"\n",
        ]
        for data in statements:
            with self.subTest(statements=data[:60]):
                path = self.anchored(data, good_proof)
                self.assertFail(run("--input", path, "--tsa-roots", roots))
                self.assertFail(run("--input", path, "--expect-kid=" + self.signer.kid, "--tsa-roots", roots))
        proofs = [
            tp.jsonl([proof_line(path="x")]), tp.jsonl([proof_line(path=[5])]), tp.jsonl([proof_line(path=["zz"])]),
            tp.jsonl([proof_line(leaf_data=5)]), tp.jsonl([proof_line(leaf_data="[1]")]),
            tp.jsonl([proof_line(leaf_data=tp.canonical({"seq": "3", "head_hash": "ef", "tenant_sha256": "00",
                                                         "v": 1}))]),
            tp.jsonl([proof_line(leaf_data=tp.canonical({"seq": 3, "head_hash": 5, "v": 1}))]),
            tp.jsonl([proof_line(anchor_seq=[1])]), tp.jsonl([proof_line(leaf_index="0")]),
            tp.jsonl([proof_line(tree_size=None)]), b"[1]\n", b"{\n",
        ]
        for data in proofs:
            with self.subTest(proofs=data[:60]):
                self.assertFail(run("--input", self.anchored(good_statement, data), "--tsa-roots", roots,
                                    "--require-anchors", "--anchored-since", "2026-01-01T00:00:00Z"))


class Usage(PackCase):
    def test_bad_pins_are_usage_errors(self):
        path = self.pack()
        for args in (("--expect-kid", "short"), ("--expect-kid", "x" * 44), ("--keys-file", "/nonexistent"),
                     ("--keys-file", self.dir)):
            with self.subTest(args=args):
                code, out, err = run("--input", path, *args)
                self.assertEqual(code, 2, out + err)
                self.assertTrue(err.startswith("FAIL: --"), err)
        bad = os.path.join(self.dir, "bad.json")
        for doc in ({"keys": [dict(self.signer.jwk(), kid="B" * 43)]}, {"keys": []}, [1], {"keys": "x"}):
            with self.subTest(doc=doc):
                with open(bad, "w") as f:
                    json.dump(doc, f)
                code, out, err = run("--input", path, "--keys-file", bad)
                self.assertEqual(code, 2, out + err)

    def test_last_resort_handler_prints_fail_instead_of_a_traceback(self):
        path = self.pack()
        original = ve._verify_pack_files

        def boom(files, pin=None):
            raise TypeError("unexpected shape")
        ve._verify_pack_files = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = ve.main(["--input", path])
        finally:
            ve._verify_pack_files = original
        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue(), "FAIL: malformed pack (TypeError: unexpected shape)\n")

    def test_help_documents_the_new_options_and_names_only_the_new_variable(self):
        code, out, err = run("--help")
        self.assertEqual(code, 0)
        for needle in ("--expect-kid KID", "--keys-file FILE", "POLICYGATE_EVIDENCE_READ_TOKEN", "Python 3.11"):
            self.assertIn(needle, out)
        self.assertEqual(set(re.findall(r"[A-Z_]*EVIDENCE_READ_TOKEN", out)), {"POLICYGATE_EVIDENCE_READ_TOKEN"})


class Online(PackCase):
    """Online mode against a local stand-in for the two endpoints it reads."""

    def serve(self, records, keys, token="t0k"):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/v1/evidence/keys"):
                    body = keys
                elif self.path.startswith("/v1/evidence/chain") \
                        and self.headers.get("Authorization") == "Bearer " + token:
                    body = {"tenant": TENANT, "records": records}
                else:
                    self.send_response(401)
                    self.end_headers()
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_address[1]

    def test_expect_kid_and_the_token_variables(self):
        url = self.serve(self.records, {"keys": [self.signer.jwk()]})
        env = {"POLICYGATE_EVIDENCE_READ_TOKEN": "t0k"}
        code, out, err = run("--base-url", url, "--tenant", TENANT, "--expect-kid=" + self.signer.kid, env=env)
        self.assertEqual(code, 0, out + err)
        self.assertIn("OK: tenant=demo records=3 seq=1..3", out)
        code, out, err = run("--base-url", url, "--tenant", TENANT, "--expect-kid=" + tp.Signer().kid, env=env)
        self.assertEqual(code, 1, out + err)
        self.assertIn("not signed by a pinned key: kid %r is not one of --expect-kid" % self.signer.kid, err)
        code, out, err = run("--base-url", url, "--tenant", TENANT)
        self.assertEqual(code, 2)
        self.assertEqual(err, "FAIL: no read token (set POLICYGATE_EVIDENCE_READ_TOKEN or pass --token)\n")

    def test_only_the_documented_token_variable_is_read(self):
        url = self.serve(self.records, {"keys": [self.signer.jwk()]})
        code, out, err = run("--base-url", url, "--tenant", TENANT, env={"OTHER_EVIDENCE_READ_TOKEN": "t0k"})
        self.assertEqual(code, 2, out + err)
        self.assertEqual(err, "FAIL: no read token (set POLICYGATE_EVIDENCE_READ_TOKEN or pass --token)\n")

    def test_malformed_responses_fail_without_a_traceback(self):
        for records, keys in (([5, "x"], {"keys": [self.signer.jwk()]}), ([dict(self.records[0], canonical=5)],
                                                                         {"keys": [self.signer.jwk()]}),
                              (self.records, {"keys": 5}), (self.records, [1]), ("x", {"keys": [self.signer.jwk()]})):
            with self.subTest(records=str(records)[:40], keys=str(keys)[:40]):
                url = self.serve(records, keys)
                code, out, err = run("--base-url", url, "--tenant", TENANT, "--token", "t0k")
                self.assertEqual(code, 1, out + err)
                self.assertNotIn("Traceback", err)
                self.assertTrue(err.startswith("FAIL: "), err)



UTC = datetime.timezone.utc


def show(label, text):
    """SHOW_OUTPUT=1 prints what the script said for each forgery (for the record; tests assert on it anyway)."""
    if os.environ.get("SHOW_OUTPUT"):
        print("\n[%s]\n%s" % (label, text), end="", file=sys.stderr)
SINCE = "2026-11-07T16:00:00Z"


def at(hour, minute):
    return datetime.datetime(2026, 11, 7, hour, minute, tzinfo=UTC)


# Fifteen records, one every 4 minutes from 16:01 (seq 1) to 16:57 (seq 15); an anchor every 10 minutes from 16:10
# sees the head as it was then. Anchoring started at 16:00 (SINCE), so with the defaults (interval 10m, grace 15m)
# a record may wait uncovered only if recorded before T + 25m, T the genTime of the latest valid anchor in the pack.
TIMES = {seq: at(16, 1 + 4 * (seq - 1)) for seq in range(1, 16)}
ANCHORS = [(3, at(16, 10)), (5, at(16, 20)), (8, at(16, 30)), (10, at(16, 40)), (13, at(16, 50))]


class AuditCase(PackCase):
    """Fifteen dated records, a throwaway TSA and its roots file; audit(path) runs the full audit command."""

    def setUp(self):
        super().setUp()
        self.tsa = tp.TestTsa()
        self.tsa_roots = self.tsa.roots_file(os.path.join(self.dir, "tsa-roots.json"))
        self.records = self.dated(TIMES)

    def dated(self, times):
        return tp.chain(self.signer, TENANT, len(times), bodies={s: {"created_at": tp.iso_ms(t)}
                                                                  for s, t in times.items()})

    def anchored_pack(self, anchors, records=None, name="pack.zip", manifest_edit=None, **kw):
        records = self.records if records is None else records
        extra, edit = tp.anchor_files(records, self.signer, TENANT, self.tsa, anchors, **kw)

        def both(m):
            edit(m)
            if manifest_edit:
                manifest_edit(m)
        return self.zip(tp.pack_files(records, self.signer, TENANT, extra_files=extra, edit=both), name)

    def audit(self, path, *more):
        return run("--input", path, "--expect-kid=" + self.signer.kid, "--tsa-roots", self.tsa_roots,
                   "--require-anchors", "--anchored-since", SINCE, *more)



@unittest.skipUnless(HAVE_ASN1, "asn1crypto not installed (see requirements-verify.txt)")
class Audit(AuditCase):
    """--require-anchors --anchored-since against packs a holder of the signing key forged (the TSA is not theirs)."""

    # the legitimate case

    def test_newest_records_waiting_for_the_next_anchor_pass(self):
        out = self.assertOk(self.audit(self.anchored_pack(ANCHORS)))
        self.assertIn("ANCHORED: seq 11..13 covered by test-tsa (Test TSA Signer) at 2026-11-07T16:50:00Z (anchor 5)",
                      out)
        self.assertIn("NOT YET ANCHORED: seq 14..15 (after 2026-11-07T16:50:00Z)", out)

    # forgeries by a key holder

    def test_forged_anchors_removed(self):
        path = self.pack(edit=lambda m: m.update(anchoring={"present": False}))
        err = self.assertFail(self.audit(path), first_bad_seq=1)
        show("forgery: anchors removed", err)
        self.assertIn("seq 1 (recorded at 2026-11-07T16:01:00Z) and the records after it are not covered by any "
                      "anchor, but seq 7 was recorded at 2026-11-07T16:25:00Z: only records recorded before "
                      "2026-11-07T16:25:00Z (--anchored-since (the pack: it carries no anchors) at "
                      "2026-11-07T16:00:00Z + interval 10m + grace 15m) may wait for the next anchor", err)

    def test_forged_anchors_removed_and_manifest_created_at_before_since(self):
        path = self.pack(edit=lambda m: m.update(anchoring={"present": False}, created_at="2026-11-07T15:00:00.000Z"))
        err = self.assertFail(self.audit(path), "and the records after it are not covered by any anchor",
                              first_bad_seq=1)
        show("forgery: anchors removed, manifest created_at before D", err)

    def test_forged_last_anchors_removed_leaving_old_records_uncovered(self):
        err = self.assertFail(self.audit(self.anchored_pack(ANCHORS[:2])), first_bad_seq=6)
        show("forgery: anchors 3..5 removed", err)
        self.assertIn("seq 6 (recorded at 2026-11-07T16:21:00Z) and the records after it are not covered by any "
                      "anchor, but seq 12 was recorded at 2026-11-07T16:45:00Z: only records recorded before "
                      "2026-11-07T16:45:00Z (the latest valid anchor 2 at 2026-11-07T16:20:00Z + interval 10m + "
                      "grace 15m)", err)
        # and the manifest's created_at cannot stretch the rule
        late = self.anchored_pack(ANCHORS[:2], name="late.zip",
                                  manifest_edit=lambda m: m.update(created_at="2026-11-07T16:21:00.000Z"))
        self.assertFail(self.audit(late), first_bad_seq=6)

    def test_forged_created_at_moved_to_hide_in_the_grace_tail(self):
        # anchors 4..5 removed: seq 15 (16:57) is past 16:30 + 25m, so the pack fails at seq 9
        self.assertFail(self.audit(self.anchored_pack(ANCHORS[:3], name="plain.zip")), first_bad_seq=9)
        for label, moved, first_bad in (("into the future", datetime.datetime(2026, 11, 8, 12, 0, tzinfo=UTC), 9),
                                        ("before D", at(15, 59), 15)):
            with self.subTest(moved=label):
                records = self.dated({**TIMES, 15: moved})
                err = self.assertFail(self.audit(self.anchored_pack(ANCHORS[:3], records=records,
                                                                    name="moved.zip")), first_bad_seq=first_bad)
                show("forgery: seq 15\'s created_at moved %s" % label, err)

    # fixes 2..7

    def test_record_created_at_without_a_time_zone_or_unparseable_fails(self):
        for value in ("2026-11-07T16:05:00", "yesterday", 5, None):
            with self.subTest(created_at=value):
                records = tp.chain(self.signer, TENANT, 3, bodies={2: {"created_at": value}})
                err = self.assertFail(run("--input", self.pack(records), "--expect-kid=" + self.signer.kid),
                                      "is not an RFC 3339 time with a time zone", first_bad_seq=2)

    def test_anchored_since_without_require_anchors_is_a_usage_error(self):
        code, out, err = run("--input", self.anchored_pack(ANCHORS), "--tsa-roots", self.tsa_roots,
                             "--anchored-since", SINCE)
        self.assertEqual(code, 2, out + err)
        self.assertEqual(err, "FAIL: --anchored-since only applies with --require-anchors (pass both, or neither)\n")

    def test_statement_kid_must_equal_its_line_kid(self):
        other = tp.Signer()

        def edit(n, st):
            if n == 2:
                st["kid"] = other.kid
        err = self.assertFail(run("--input", self.anchored_pack(ANCHORS, statement_edit=edit), "--tsa-roots",
                                  self.tsa_roots),
                              "anchor 2: the statement names kid %r, the line that carries it kid %r"
                              % (other.kid, self.signer.kid))
        self.assertIn("anchor 2 does not verify, so it covers nothing", err)

    def test_no_plain_anchored_line_for_a_range_with_a_failed_record(self):
        path = self.anchored_pack(ANCHORS)
        with zipfile.ZipFile(path) as z:
            entries = {n: z.read(n) for n in z.namelist()}
        lines = [json.loads(x) for x in entries["records.jsonl"].decode().splitlines()]
        lines[1]["canonical"] = lines[1]["canonical"].replace('"outcome":"allow"', '"outcome":"deny"')
        entries["records.jsonl"] = tp.jsonl(lines)
        # a forger without the key cannot re-sign the manifest: the file hash fails too, as it should
        code, out, err = run("--input", self.zip(entries, name="edited.zip"), "--tsa-roots", self.tsa_roots)
        self.assertEqual(code, 1, out + err)
        show("fix 5: seq 2 edited inside anchor 1's range", out + err)
        self.assertNotIn("ANCHORED: seq 1..3", out)
        self.assertIn("ANCHOR CHECKED, RECORDS FAILED: seq 1..3: anchor 1 (test-tsa (Test TSA Signer) at "
                      "2026-11-07T16:10:00Z) verifies, but seq 2 in this range failed its own checks (see the FAIL "
                      "lines), so the range is not proven", out)
        self.assertIn("ANCHORED: seq 4..5 covered by test-tsa", out)
        self.assertTrue(err.startswith("FAIL: first bad seq 2 ("), err)

    def test_expect_kid_that_starts_with_a_dash(self):
        signer = tp.Signer()
        while not signer.kid.startswith("-"):
            signer = tp.Signer()
        path = self.zip(tp.pack_files(tp.chain(signer, TENANT, 2), signer, TENANT), name="dash.zip")
        out = self.assertOk(run("--input", path, "--expect-kid", signer.kid))
        self.assertNotIn("KEY NOT PINNED", out)
        self.assertOk(run("--input", path, "--expect-kid=" + signer.kid))
        self.assertFail(run("--input", path, "--expect-kid", "-" + "A" * 42), "is not one of --expect-kid")

    def test_usage_examples_name_example_bank(self):
        code, out, err = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("evidence-example-bank.zip", out)
        self.assertIn("--tenant example-bank", out)
        self.assertNotIn("acme", out)


def table_row(label, result):
    """ATTACK_TABLE=<file> appends "label | exit | first line" for each attempt (the report's table)."""
    code, out, err = result
    first = (err.splitlines() or [""])[0] if code else (out.splitlines() or [""])[0]
    path = os.environ.get("ATTACK_TABLE")
    if path:
        with open(path, "a") as f:
            f.write("%s | %d | %s\n" % (label, code, first))
    return result


def lines_of(data):
    return [json.loads(x) for x in data.decode().splitlines() if x.strip()]


@unittest.skipUnless(HAVE_ASN1, "asn1crypto not installed (see requirements-verify.txt)")
class KeyHolder(AuditCase):
    """The key holder's attempts against the full audit command (--expect-kid, --tsa-roots, --require-anchors,
    --anchored-since) with real statements, tokens and proofs of an honest pack. Each changes, removes, adds or
    reorders a record an honest anchor covered and must FAIL; the test_residual_* cases exit 0 and are the documented
    limits of one pack (SPEC.md, section 10, "What a key holder can still do")."""

    def changed(self, seqs=(), times=None, n=15):
        """The chain re-signed by the key holder: outcome "deny" at `seqs`, created_at from `times`."""
        times = {**TIMES, **(times or {})}
        return tp.chain(self.signer, TENANT, n, bodies={
            s: dict({"created_at": tp.iso_ms(times[s])}, **({"outcome": "deny"} if s in seqs else {}))
            for s in range(1, n + 1)})

    def forge(self, records=None, anchors=ANCHORS, mutate=None, manifest_edit=None, name="forged.zip"):
        """Honest anchor files (statements, proofs, tokens over the honest chain), then mutate(files, anchoring),
        then a pack of `records` whose manifest the key holder re-signs."""
        others = []
        extra, edit = tp.anchor_files(self.records, self.signer, TENANT, self.tsa, anchors, other_proofs=others)
        m0 = {}
        edit(m0)
        anch = m0["anchoring"]
        self.others = others
        if mutate:
            mutate(extra, anch)

        def final(m):
            m["anchoring"] = anch
            if manifest_edit:
                manifest_edit(m)
        return self.zip(tp.pack_files(self.records if records is None else records, self.signer, TENANT,
                                      extra_files=extra, edit=final), name)

    def attempt(self, label, path, *more, code=1, needle=None, first_bad_seq=None):
        result = table_row(label, self.audit(path, *more))
        if code == 1:
            self.assertFail(result, *([needle] if needle else []), first_bad_seq=first_bad_seq)
        else:
            self.assertOk(result)
        return result

    @staticmethod
    def drop_proofs(*anchors):
        def mutate(files, anch):
            kept = [p for p in lines_of(files["anchors/proofs.jsonl"]) if p["anchor_seq"] not in anchors]
            files["anchors/proofs.jsonl"] = tp.jsonl(kept)
            anch["proofs"] = len(kept)
        return mutate

    # proofs

    def test_all_proofs_left_out(self):
        # the reported bypass: real statements and tokens, no proof, records as they are
        path = self.forge(mutate=self.drop_proofs(1, 2, 3, 4, 5))
        self.attempt("all proofs left out (records unchanged)", path, needle="have no proof for this tenant")
        code, out, err = run("--input", path, "--expect-kid=" + self.signer.kid, "--tsa-roots", self.tsa_roots)
        self.assertEqual(code, 0, out + err)
        self.assertIn("WARNING: pack invariant broken: anchor(s) 1, 2, 3, 4, 5 have no proof for this tenant", out)
        self.assertIn("NOT YET ANCHORED: seq 1..15 (no anchor in this pack verifies with a checked proof", out)
        # and with every record rewritten: T is D, not anchor 5's genTime
        err = self.attempt("all proofs left out, seq 2 rewritten", self.forge(
            self.changed({2}), mutate=self.drop_proofs(1, 2, 3, 4, 5)), first_bad_seq=1)[2]
        self.assertIn("(--anchored-since (the pack: none of its anchors verifies with a checked proof for this "
                      "tenant) at 2026-11-07T16:00:00Z + interval 10m + grace 15m)", err)

    def test_newest_proofs_left_out(self):
        self.attempt("proofs of anchors 4..5 left out, seq 11 rewritten",
                     self.forge(self.changed({11}), mutate=self.drop_proofs(4, 5)),
                     needle="this tenant's leaf is missing")

    def test_another_tenants_real_proof(self):
        def mutate(files, anch):
            files["anchors/proofs.jsonl"] = tp.jsonl(
                [p for p in lines_of(files["anchors/proofs.jsonl"]) if p["anchor_seq"] != 5] + [self.others[4]])
        self.attempt("anchor 5's proof replaced by another tenant's real proof, seq 12 rewritten",
                     self.forge(self.changed({12}), mutate=mutate), needle="the leaf is not this tenant's")

    def test_duplicate_or_reordered_proofs(self):
        def duplicate(files, anch):
            proofs = lines_of(files["anchors/proofs.jsonl"])
            bogus = dict(proofs[4], path=["00" * 32] * 4)
            files["anchors/proofs.jsonl"] = tp.jsonl(proofs[:4] + [bogus, proofs[4]])
            anch["proofs"] = 6
        self.attempt("a second (bogus) proof for anchor 5", self.forge(mutate=duplicate),
                     needle="holds 2 proofs for anchor 5")

        def reorder(files, anch):
            files["anchors/proofs.jsonl"] = tp.jsonl(list(reversed(lines_of(files["anchors/proofs.jsonl"]))))
        self.attempt("proofs in reverse order", self.forge(mutate=reorder, name="reorder.zip"),
                     needle="not in anchor order")

    # statements

    def test_statement_left_out_proof_and_token_kept(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[:4])
            anch.update(last_anchor_seq=4, anchors=4)
        self.attempt("statement 5 left out, its proof and token kept, seq 12 rewritten",
                     self.forge(self.changed({12}), mutate=mutate), needle="whose statement is missing")

    def test_statements_and_proofs_left_out_tokens_kept(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[:3])
            files["anchors/proofs.jsonl"] = tp.jsonl(lines_of(files["anchors/proofs.jsonl"])[:3])
            anch.update(last_anchor_seq=3, anchors=3, proofs=3)
        self.attempt("statements and proofs 4..5 left out, tokens 4..5 kept, seq 9..15 re-dated before 16:55",
                     self.forge(self.changed({9, 10}, {12: at(16, 46), 13: at(16, 48), 14: at(16, 50),
                                                       15: at(16, 52)}), mutate=mutate),
                     needle="a token entry names anchor 4, which has no statement in the pack")

    def test_statements_proofs_and_tokens_left_out_with_honest_times(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[:3])
            files["anchors/proofs.jsonl"] = tp.jsonl(lines_of(files["anchors/proofs.jsonl"])[:3])
            for n in (4, 5):
                del files["anchors/tokens/%d-test-tsa.tsr" % n]
            anch.update(last_anchor_seq=3, anchors=3, proofs=3, tokens=anch["tokens"][:3])
        self.attempt("anchors 4..5 left out entirely, seq 9 rewritten, times unchanged",
                     self.forge(self.changed({9}), mutate=mutate), first_bad_seq=9)

    def test_every_combination_of_statement_proof_and_token_left_out(self):
        import itertools
        for k in (1, 2, 3):
            for parts in itertools.combinations(("statement", "proof", "token"), k):
                def mutate(files, anch, parts=parts):
                    if "statement" in parts:
                        files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[:4])
                        anch.update(last_anchor_seq=4, anchors=4)
                    if "proof" in parts:
                        files["anchors/proofs.jsonl"] = tp.jsonl(lines_of(files["anchors/proofs.jsonl"])[:4])
                        anch["proofs"] = 4
                    if "token" in parts:
                        del files["anchors/tokens/5-test-tsa.tsr"]
                        anch["tokens"] = anch["tokens"][:4]
                # all three gone is a pack that ends before anchor 5 existed: the residual "newest anchors left
                # out" (T = anchor 4 at 16:40, every uncovered record is before 17:05)
                residual = len(parts) == 3
                with self.subTest(left_out=parts):
                    self.attempt(("RESIDUAL: " if residual else "") + "anchor 5's %s left out, seq 12 rewritten"
                                 % " + ".join(parts), self.forge(self.changed({12}), mutate=mutate,
                                                                 name="combo.zip"), code=0 if residual else 1)

    def test_first_anchors_left_out(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[2:])
            files["anchors/proofs.jsonl"] = tp.jsonl(lines_of(files["anchors/proofs.jsonl"])[2:])
            for n in (1, 2):
                del files["anchors/tokens/%d-test-tsa.tsr" % n]
            anch.update(first_anchor_seq=3, anchors=3, proofs=3, tokens=anch["tokens"][2:])
        self.attempt("anchors 1..2 left out, seq 2 rewritten (anchor 3 covers 1..8)",
                     self.forge(self.changed({2}), mutate=mutate), first_bad_seq=1,
                     needle="seq 8 does not match the head anchored")

    def test_anchor_before_the_pack_with_more_anchors(self):
        records = self.records[3:]
        self.attempt("pack starts at seq 4 but keeps anchor 1 (head 3)", self.forge(records),
                     needle="the pack's first anchor 1 saw seq 3, before the pack's first seq 4")

    def test_only_the_latest_statement_without_proof(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = tp.jsonl(lines_of(files["anchors/statements.jsonl"])[4:])
            files["anchors/proofs.jsonl"] = b""
            for n in (1, 2, 3, 4):
                del files["anchors/tokens/%d-test-tsa.tsr" % n]
            anch.update(first_anchor_seq=5, anchors=1, proofs=0, tokens=anch["tokens"][4:])
        self.attempt("only anchor 5 kept, no proof (\"tenant was new\"), seq 2 rewritten",
                     self.forge(self.changed({2}), mutate=mutate), first_bad_seq=1)
        late = {s: at(16, 45) + datetime.timedelta(seconds=20 * s) for s in range(1, 16)}
        self.attempt("only anchor 5 kept, no proof, all records re-dated after it",
                     self.forge(self.changed({2}, late), mutate=mutate, name="late.zip"), first_bad_seq=1)

    # tokens

    def test_tokens_left_out(self):
        def mutate(files, anch):
            for n in range(1, 6):
                del files["anchors/tokens/%d-test-tsa.tsr" % n]
            anch["tokens"] = []
        self.attempt("all token files and entries left out", self.forge(mutate=mutate),
                     needle="no valid TSA token")

    def test_token_files_swapped(self):
        def mutate(files, anch):
            a, b = "anchors/tokens/4-test-tsa.tsr", "anchors/tokens/5-test-tsa.tsr"
            files[a], files[b] = files[b], files[a]
        self.attempt("token files of anchors 4 and 5 swapped", self.forge(mutate=mutate),
                     needle="anchor 4: no valid TSA token")

    def test_token_entry_pointing_at_another_file(self):
        def mutate(files, anch):
            anch["tokens"][4]["file"] = "anchors/tokens/4-test-tsa.tsr"
            del files["anchors/tokens/5-test-tsa.tsr"]
        self.attempt("anchor 5's token entry points at anchor 4's file", self.forge(mutate=mutate),
                     needle="anchor 5: no valid TSA token")

        def extra(files, anch):
            anch["tokens"].append({"anchor_seq": 5, "tsa": "test-tsa", "file": "anchors/tokens/4-test-tsa.tsr"})
        self.attempt("an extra token entry for anchor 5 pointing at anchor 4's file",
                     self.forge(mutate=extra, name="extra.zip"), needle="points at anchors/tokens/4-test-tsa.tsr")

    def test_token_file_without_entry(self):
        def mutate(files, anch):
            anch["tokens"] = anch["tokens"][:4]
        self.attempt("anchor 5's token entry left out, its file kept", self.forge(mutate=mutate),
                     needle="anchors/tokens/5-test-tsa.tsr is not named by any token entry")

    # re-dating

    def test_redated_around_d(self):
        times = {s: at(15, 30) + datetime.timedelta(minutes=s) for s in range(9, 16)}
        self.attempt("anchors 1..3 kept, seq 9..15 rewritten and re-dated before D",
                     self.forge(self.changed({9}, times), anchors=ANCHORS[:3]), first_bad_seq=9,
                     needle="backdated")

    def test_redated_around_t(self):
        self.attempt("seq 15 re-dated to T + 25m exactly (17:15)",
                     self.forge(self.changed({15}, {15: at(17, 15)})), first_bad_seq=14)

    def test_creeping_back_under_five_minutes_per_record(self):
        times = {s: at(16, 1) - datetime.timedelta(minutes=4 * (s - 1)) for s in range(1, 16)}
        path = self.pack(self.changed({2}, times), edit=lambda m: m.update(anchoring={"present": False}))
        self.attempt("anchors stripped, each record 4 min before the previous (to before D)", path,
                     first_bad_seq=3, needle="records re-dated out of order")

    # anchor files

    def test_empty_anchor_files(self):
        def mutate(files, anch):
            files["anchors/statements.jsonl"] = b""
            files["anchors/proofs.jsonl"] = b""
        self.attempt("statements.jsonl and proofs.jsonl empty", self.forge(mutate=mutate),
                     needle="holds no statement")

    def test_anchors_in_manifest_but_not_in_pack(self):
        def mutate(files, anch):
            for name in list(files):
                del files[name]
        self.attempt("anchoring.present true, no anchors/ file at all", self.forge(mutate=mutate),
                     needle="anchors/statements.jsonl is missing")

        def declared(m):
            m["files"]["anchors/proofs.jsonl"] = {"sha256": "00" * 32, "bytes": 0}

        def without_proofs(files, anch):
            del files["anchors/proofs.jsonl"]
        self.attempt("proofs.jsonl declared in the manifest, missing from the pack",
                     self.forge(mutate=without_proofs, manifest_edit=declared, name="declared.zip"),
                     needle="declared in the manifest but missing from the pack")

    def test_anchor_files_with_anchoring_present_false(self):
        self.attempt("anchor files kept, anchoring.present false",
                     self.forge(self.changed({2}), manifest_edit=lambda m: m.update(anchoring={"present": False})),
                     needle="the manifest says the pack carries no anchors, yet it holds")

    def test_interval_and_grace_cannot_come_from_the_pack(self):
        def knobs(m):
            m["anchoring"].update(interval="24h", grace="24h", anchor_interval="24h", anchor_grace="24h")
            m.update(anchor_interval="24h", anchor_grace="24h", interval="24h", grace="24h")
        err = self.attempt("anchors 3..5 removed, interval/grace of 24h written into the manifest",
                           self.forge(anchors=ANCHORS[:2], manifest_edit=knobs), first_bad_seq=6)[2]
        self.assertIn("(the latest valid anchor 2 at 2026-11-07T16:20:00Z + interval 10m + grace 15m)", err)

    # an anchor whose head lies beyond the pack

    def test_anchor_head_beyond_the_pack(self):
        def head(m):
            m["chain_head"] = {"seq": 15, "hash": self.records[14]["body_sha256"]}
        path = self.forge(self.changed({9}, n=9), manifest_edit=head)
        code, out, err = run("--input", path, "--expect-kid=" + self.signer.kid, "--tsa-roots", self.tsa_roots)
        show("records 1..9 only, seq 9 rewritten, anchors 1..5 kept (b1b4832 printed ANCHORED: seq 9..9)", out + err)
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("ANCHORED: seq 9..9 covered", out)
        self.assertIn("ANCHOR BEYOND THIS PACK: anchor 4 saw seq 10, after this pack's last seq 9", out)
        self.assertIn("NOT YET ANCHORED: seq 9..9 (after 2026-11-07T16:30:00Z)", out)
        self.attempt("records 1..9 only, seq 9 rewritten, anchors 1..5 kept", path,
                     needle="anchor 4 already covers the pack's last seq 9, yet later anchors follow")

    # what one pack cannot prevent (SPEC.md, section 10)

    def test_residual_keep_old_anchors_rewrite_and_redate_the_rest(self):
        times = {s: at(16, 21) + datetime.timedelta(minutes=2 * (s - 6)) for s in range(6, 16)}

        def mutate(files, anch):
            pass
        self.attempt("RESIDUAL: anchors 1..2 kept, seq 6..15 rewritten and re-dated to 16:21..16:39",
                     self.forge(self.changed({6, 9, 12}, times), anchors=ANCHORS[:2]), code=0)

    def test_residual_pack_ends_before_the_last_anchor_head(self):
        def head(m):
            m["chain_head"] = {"seq": 15, "hash": self.records[14]["body_sha256"]}
        self.attempt("RESIDUAL: records 1..9, anchors 1..4 (4 saw seq 10), seq 9 rewritten",
                     self.forge(self.changed({9}, n=9), anchors=ANCHORS[:4], manifest_edit=head), code=0)

    def test_residual_uncovered_tail_rewritten_before_t_plus_25m(self):
        self.attempt("RESIDUAL: seq 15 (not yet anchored) rewritten and re-dated to 17:14",
                     self.forge(self.changed({15}, {15: at(17, 14)})), code=0)

    def test_residual_everything_stripped_and_redated_before_d(self):
        times = {s: at(15, 0) + datetime.timedelta(minutes=3 * s) for s in range(1, 16)}
        self.attempt("RESIDUAL: anchors stripped, every record rewritten and re-dated before D",
                     self.pack(self.changed({2}, times), edit=lambda m: m.update(anchoring={"present": False})),
                     code=0)


if __name__ == "__main__":
    unittest.main()
