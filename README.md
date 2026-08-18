# Coldpack

Simple encrypted archives for cold files

## Usage

Create a pack (the passphrase is requested twice):

```console
python3 coldpack.py pack ROOT DEST PACK_ID
```

This creates `coldpack-PACK_ID.tar.zst.age` and an encrypted JSON Lines
manifest in `DEST`.

Extract a pack (the passphrase is requested once):

```console
python3 coldpack.py extract ARCHIVE DEST
```

Coldpack requires `tar`, `zstd`, `age`, and `age-plugin-batchpass` on `PATH`.
