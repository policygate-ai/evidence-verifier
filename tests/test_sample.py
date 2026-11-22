"""The sample packs in sample/: the real pack verifies, the tampered copy fails, and the files on disk are what the
zips hold. Each case runs verify-evidence.py as a user would (python3 -I verify-evidence.py ...)."""
import json
import os
import re
import subprocess
import sys
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "verify-evidence.py")
ROOTS = os.path.join(ROOT, "tsa-roots.json")
SAMPLE = os.path.join(ROOT, "sample")
PACK_ZIP = os.path.join(SAMPLE, "example-bank.zip")
PACK_DIR = os.path.join(SAMPLE, "example-bank")
TAMPERED_ZIP = os.path.join(SAMPLE, "example-bank-tampered.zip")
TAMPERED_DIR = os.path.join(SAMPLE, "example-bank-tampered")
KID = "0rTFPXvZBXeF6fNuK8MDDc-mN6_PAAaVT60mzCGEDEk"
ANCHORED_SINCE = "2026-11-07T16:07:00Z"  # the reference deployment's first anchor
OTHER_KID = "A" * 43


def run(*args):
    """(exit code, stdout, stderr) of the verifier."""
    p = subprocess.run([sys.executable, "-I", SCRIPT] + list(args), capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def zip_files(path):
    """{name: bytes} of every file entry in a zip."""
    with zipfile.ZipFile(path) as z:
        return {i.filename: z.read(i.filename) for i in z.infolist() if not i.is_dir()}


def dir_files(path):
    """{name: bytes} of every file under a directory, names with "/" separators."""
    out = {}
    for root, _, names in os.walk(path):
        for name in names:
            full = os.path.join(root, name)
            with open(full, "rb") as f:
                out[os.path.relpath(full, path).replace(os.sep, "/")] = f.read()
    return out


def flatten(value, prefix=""):
    """{json path: leaf value} of a parsed JSON value."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out.update(flatten(v, "%s/%s" % (prefix, k)))
        return out
    if isinstance(value, list):
        out = {}
        for i, v in enumerate(value):
            out.update(flatten(v, "%s/%d" % (prefix, i)))
        return out
    return {prefix: value}


def anchored_seqs(out):
    """Every seq that an ANCHORED line covers."""
    seqs = set()
    for a, b in re.findall(r"^ANCHORED: seq (\d+)\.\.(\d+) covered by ", out, re.M):
        seqs.update(range(int(a), int(b) + 1))
    return seqs


class Sample(unittest.TestCase):
    def test_sample_verifies_pinned_with_roots_and_all_records_anchored(self):
        for path in (PACK_ZIP, PACK_DIR):
            with self.subTest(path=path):
                code, out, err = run("--input", path, "--expect-kid=" + KID, "--tsa-roots", ROOTS)
                self.assertEqual(code, 0, out + err)
                self.assertEqual(err, "")
                self.assertIn("OK: pack=%s tenant=example-bank records=7 seq=1..7 " % path, out)
                self.assertEqual(anchored_seqs(out), set(range(1, 8)))
                self.assertIn("(anchor 358)", out)
                self.assertIn("(anchor 359)", out)
                self.assertNotIn("NOT YET ANCHORED", out)
                self.assertNotIn("KEY NOT PINNED", out)

    def test_sample_without_a_pin_says_key_not_pinned(self):
        code, out, err = run("--input", PACK_ZIP, "--tsa-roots", ROOTS)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(out.splitlines()[-1], "KEY NOT PINNED: verified against the key inside this pack (kid %s). "
                         "Compare it with the signer's published key, or pass --expect-kid." % KID)

    def test_sample_with_a_wrong_expect_kid_fails(self):
        code, out, err = run("--input", PACK_ZIP, "--expect-kid=" + OTHER_KID, "--tsa-roots", ROOTS)
        self.assertEqual(code, 1, out + err)
        self.assertNotIn("OK: pack=", out)
        self.assertIn("the manifest is not signed by a pinned key: kid %r is not one of --expect-kid" % KID, err)

    def test_tampered_copy_fails(self):
        for path in (TAMPERED_ZIP, TAMPERED_DIR):
            with self.subTest(path=path):
                code, out, err = run("--input", path, "--expect-kid=" + KID, "--tsa-roots", ROOTS)
                self.assertEqual(code, 1, out + err)
                self.assertNotIn("OK: pack=", out)
                self.assertTrue(err.startswith("FAIL: first bad seq 3 ("), err)
                self.assertIn("seq 3 (id 431f8ed7-887c-43d6-b546-cb04166ad39a): signature INVALID", err)
                self.assertIn("records.jsonl: sha256 ", err)

    def test_audit_command_passes_on_the_sample(self):
        for path in (PACK_ZIP, PACK_DIR):
            with self.subTest(path=path):
                code, out, err = run("--input", path, "--expect-kid", KID, "--tsa-roots", ROOTS,
                                     "--require-anchors", "--anchored-since", ANCHORED_SINCE)
                self.assertEqual(code, 0, out + err)
                self.assertEqual(err, "")
                self.assertIn("OK: pack=%s tenant=example-bank records=7 seq=1..7 " % path, out)
                self.assertEqual(anchored_seqs(out), set(range(1, 8)))

    def test_tampered_copy_prints_anchor_checked_records_failed_for_its_range(self):
        for path in (TAMPERED_ZIP, TAMPERED_DIR):
            with self.subTest(path=path):
                code, out, err = run("--input", path, "--expect-kid", KID, "--tsa-roots", ROOTS,
                                     "--require-anchors", "--anchored-since", ANCHORED_SINCE)
                self.assertEqual(code, 1, out + err)
                self.assertIn("ANCHORED: seq 1..1 covered by freetsa (www.freetsa.org) at 2026-11-21T15:21:29Z "
                              "(anchor 358)", out)
                self.assertIn("ANCHOR CHECKED, RECORDS FAILED: seq 2..7: anchor 359 (freetsa (www.freetsa.org) at "
                              "2026-11-21T15:31:30Z) verifies, but seq 3 in this range failed its own checks (see the "
                              "FAIL lines), so the range is not proven", out)
                self.assertEqual(anchored_seqs(out), {1})
                self.assertNotRegex(out, r"(?m)^ANCHORED: seq 2\.\.7 ")
                self.assertTrue(err.startswith("FAIL: first bad seq 3 ("), err)

    def test_unpacked_directories_equal_the_zips(self):
        for zip_path, dir_path in ((PACK_ZIP, PACK_DIR), (TAMPERED_ZIP, TAMPERED_DIR)):
            with self.subTest(zip=zip_path):
                self.assertEqual(dir_files(dir_path), zip_files(zip_path))

    def test_tampered_copy_differs_in_exactly_one_field(self):
        good, bad = zip_files(PACK_ZIP), zip_files(TAMPERED_ZIP)
        with zipfile.ZipFile(PACK_ZIP) as a, zipfile.ZipFile(TAMPERED_ZIP) as b:
            self.assertEqual(a.namelist(), b.namelist())
        self.assertEqual([n for n in good if good[n] != bad[n]], ["records.jsonl"])
        good_lines = good["records.jsonl"].split(b"\n")
        bad_lines = bad["records.jsonl"].split(b"\n")
        self.assertEqual(len(good_lines), len(bad_lines))
        changed = [i for i in range(len(good_lines)) if good_lines[i] != bad_lines[i]]
        self.assertEqual(changed, [2])  # the third line: seq 3
        good_record, bad_record = json.loads(good_lines[2]), json.loads(bad_lines[2])
        self.assertEqual(good_record["seq"], 3)
        self.assertEqual({k: v for k, v in good_record.items() if k != "canonical"},
                         {k: v for k, v in bad_record.items() if k != "canonical"})
        self.assertEqual(bad_record["canonical"],
                         good_record["canonical"].replace('"outcome":"deny"', '"outcome":"allow"'))
        before, after = flatten(json.loads(good_record["canonical"])), flatten(json.loads(bad_record["canonical"]))
        self.assertEqual(before.keys(), after.keys())
        self.assertEqual({k: (before[k], after[k]) for k in before if before[k] != after[k]},
                         {"/outcome": ("deny", "allow")})

    def test_sample_holds_the_records_the_readme_describes(self):
        lines = zip_files(PACK_ZIP)["records.jsonl"].decode("utf-8").splitlines()
        bodies = [json.loads(json.loads(line)["canonical"]) for line in lines]
        self.assertEqual([b["seq"] for b in bodies], list(range(1, 8)))
        self.assertEqual([b["outcome"] for b in bodies],
                         ["applied", "allow", "deny", "allow", "deny", "deny", "allow"])
        self.assertEqual(bodies[0]["decision_type"], "admin_change")
        self.assertEqual({b["subject"] for b in bodies[1:]}, {"support-assistant"})
        self.assertEqual([b["payload"]["model"] for b in bodies[1:]],
                         ["gpt-4o-mini", "gpt-4o", "gpt-4o-mini", "gpt-4o-mini", "gpt-4o-mini", "gpt-4o-mini"])
        self.assertIn("x-policy-reason=model.not_allowed", bodies[2]["reasons"])
        self.assertIn("x-policy-reason=authz.missing_scope", bodies[4]["reasons"])
        self.assertIn("x-policy-reason=residency.jwt_region_mismatch", bodies[5]["reasons"])
        self.assertEqual({b["payload"]["host"] for b in bodies[1:]}, {"127.0.0.1:10000"})


if __name__ == "__main__":
    unittest.main()
