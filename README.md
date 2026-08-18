# Coldpack

Simple encrypted archives for cold files

## Usage

Create a pack (the passphrase is requested twice):

```console
python3 coldpack.py pack ROOT DEST PACK_PREFIX
```

Coldpack automatically adds the next three-digit numeric version to the prefix.
For example, the first pack using prefix `2026-aug` creates
`coldpack-2026-aug-000.tar.zst.age` and
`coldpack-2026-aug-000.jsonl.age`. The next invocation with the same prefix
uses version `001`.

Extract a pack (the passphrase is requested once):

```console
python3 coldpack.py extract ARCHIVE DEST
```

Decrypt a pack manifest to standard output (the passphrase is requested once):

```console
python3 coldpack.py manifest MANIFEST.jsonl.age
```

Coldpack requires `tar`, `zstd`, `age`, and `age-plugin-batchpass` on `PATH`.
