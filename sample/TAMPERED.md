# The tampered copy

`example-bank-tampered.zip` (and `example-bank-tampered/`, the same files unpacked) is `example-bank.zip` with one
field changed. In record seq 3, the outcome `deny` became `allow`: the denied `gpt-4o` call is made to look
allowed.

Nothing else changed. The record was not re-signed, its `body_sha256` was not updated, and the manifest was not
fixed. Every other file in the zip has the same content, name and place in the order. (The zip itself was
rebuilt, so its compressed size differs.)

The change, in line 3 of `records.jsonl` (the record is one long line; `...` stands for the unchanged parts before
and after):

```diff
--- example-bank/records.jsonl (line 3, seq 3)
+++ example-bank-tampered/records.jsonl (line 3, seq 3)
-...\"input_sha256\":\"e349e58acfb4908898b67013ce6352077903ce2d7b13ce6080e27f48b71e8199\",\"outcome\":\"deny\",\"payload\":...
+...\"input_sha256\":\"e349e58acfb4908898b67013ce6352077903ce2d7b13ce6080e27f48b71e8199\",\"outcome\":\"allow\",\"payload\":...
```

The backslashes are there because the signed body (`canonical`) is a JSON string inside the record line.

To see the full difference yourself:

```
diff example-bank/records.jsonl example-bank-tampered/records.jsonl
```

What the verifier reports, and why:

- `sha256(canonical) != body_sha256`: the signed body no longer hashes to the value stored with it.
- `signature INVALID`: the signature was made over the original body.
- `records.jsonl: sha256 ... does not match the manifest`: the signed manifest holds the hash of the original file.
- `ANCHOR CHECKED, RECORDS FAILED: seq 2..7: ...`: anchor 359 still verifies, because the record hashes it fixes are
  unchanged, but seq 3 in its range failed its own checks. So the range is not reported as `ANCHORED`.

To hide the change, a forger would have to re-sign the record and every later link, and the manifest. That needs
the private key. With a pack forged under a new key, `--expect-kid` fails it. And records that are already
anchored would no longer match the head hashes the time-stamp authority dated.

SHA-256 of the two zips:

```
f6453b727f1a7049a03a907ed10aa028f503c43d29920548b283b806d915b7ac  example-bank.zip
22e127bad3857d360e4789e65d29880b5ca43d3722e90622fa461d50e52967a2  example-bank-tampered.zip
```
