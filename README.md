# Coldpack

Simple encrypted archives for cold files

## Usage

Create a pack (the passphrase is requested twice):

```console
python3 coldpack.py pack ROOT DEST PACK_ID
```

Coldpack adds the current UTC date and time to the supplied pack ID. For example,
a pack using ID `2026-aug` might create:

```text
coldpack-2026-aug-2026-08-18T143052Z.tar.gz.age
coldpack-2026-aug-2026-08-18T143052Z.manifest.jsonl.age
```

Every pack is a complete, independent archive. The encrypted sidecar manifest
lists each archived regular file with its BLAKE2b hash, size, modification time,
while the manifest header identifies the full pack. Coldpack refuses to overwrite
an existing archive or manifest if two invocations select the same timestamp.

Extract a pack (the passphrase is requested once):

```console
python3 coldpack.py extract ARCHIVE DEST
```

Decrypt a pack manifest to standard output (the passphrase is requested once):

```console
python3 coldpack.py manifest MANIFEST.manifest.jsonl.age
```

Coldpack requires Python 3, `tar`, `gzip`, `age`, and
`age-plugin-batchpass` on `PATH`. Gzip is used instead of Zstandard to maximize
the chance that the compression format is already available in a minimal
disaster-recovery environment.
