# Coldpack

Simple encrypted archives for cold files

## Usage

Create a pack (the passphrase is requested twice):

```console
python3 coldpack.py pack ROOT DEST PACK_ID
```

Coldpack automatically adds the next three-digit pack version to the pack ID.
For example, the first pack using ID `2026-aug` creates
`coldpack-2026-aug-000.tar.zst.age` and
`coldpack-2026-aug-000.jsonl.age`. The next invocation with the same pack ID
uses version `001`.

Each version archives only `(path, hash)` pairs not already witnessed by the
series. Its manifest remains cumulative: it contains every file version seen in
the series and records the pack version where that content was first stored.
Creating a later version requires the same passphrase as the previous version,
which Coldpack validates before hashing or creating any new artifacts.

Extract a pack (the passphrase is requested once):

```console
python3 coldpack.py extract ARCHIVE DEST
```

Decrypt a pack manifest to standard output (the passphrase is requested once):

```console
python3 coldpack.py manifest MANIFEST.jsonl.age
```

Coldpack requires `tar`, `zstd`, `age`, and `age-plugin-batchpass` on `PATH`.
