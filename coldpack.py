import getpass
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

CHUNK_SIZE = 1024 * 1024

@dataclass
class FileRecord:
    path: str
    hash_algo: str
    hash: str
    size: int
    mtime_ns: int
    pack: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "path": self.path,
                "hash": f"{self.hash_algo}:{self.hash}",
                "size": self.size,
                "mtime_ns": self.mtime_ns,
                "pack": self.pack,
            },
            separators=(",", ":"),
        )


def require_tools() -> None:
    for tool in ("tar", "zstd", "age", "age-plugin-batchpass"):
        if shutil.which(tool) is None:
            raise SystemExit(f"required tool not found: {tool}")


def hash_file(path: Path) -> tuple[str,str]:
    h = hashlib.blake2b()

    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)

    return "blake2b", h.hexdigest()


def walk_files(root: Path) -> Iterable[Path]:
    root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)

        for name in filenames:
            path = base / name

            if path.is_symlink():
                continue

            if path.is_file():
                yield path


def scan(root: Path, pack_id: str) -> list[FileRecord]:
    records = []

    for path in walk_files(root):
        st = path.stat()
        rel = path.relative_to(root).as_posix()

        print(f"hashing {rel}", file=sys.stderr)

        hash_algo, hash = hash_file(path)

        records.append(
            FileRecord(
                path=rel,
                hash_algo=hash_algo,
                hash=hash,
                size=st.st_size,
                mtime_ns=st.st_mtime_ns,
                pack=pack_id,
            )
        )

    return records


def make_passphrase_pipe(passphrase: str) -> tuple[int, int]:
    """
    Return (read_fd, write_fd).

    age-plugin-batchpass will inherit read_fd.
    """
    rfd, wfd = os.pipe()

    os.write(wfd, passphrase.encode("utf-8"))
    os.close(wfd)

    return rfd, -1


def age_encrypt_process(
    *,
    stdin,
    stdout,
    passphrase: str,
) -> subprocess.Popen:
    """
    Start:

        age -e -j batchpass

    with AGE_PASSPHRASE_FD pointing at a private inherited pipe.
    """
    rfd, _ = make_passphrase_pipe(passphrase)

    env = os.environ.copy()
    env["AGE_PASSPHRASE_FD"] = str(rfd)

    try:
        proc = subprocess.Popen(
            [
                "age",
                "-e",
                "-j",
                "batchpass",
            ],
            stdin=stdin,
            stdout=stdout,
            env=env,
            pass_fds=(rfd,),
        )
    finally:
        os.close(rfd)

    return proc


def encrypt_file(
    source: Path,
    destination: Path,
    passphrase: str,
) -> None:
    with source.open("rb") as src, destination.open("wb") as dst:
        proc = age_encrypt_process(
            stdin=src,
            stdout=dst,
            passphrase=passphrase,
        )

        rc = proc.wait()

    if rc != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"age failed with exit status {rc}")


def write_manifest(
    path: Path,
    pack_id: str,
    records: Iterable[FileRecord],
) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        header = {
            "type": "pack",
            "version": 1,
            "pack": pack_id,
        }

        f.write(json.dumps(header, separators=(",", ":")) + "\n")

        for record in records:
            f.write(record.to_json() + "\n")


def create_archive(
    root: Path,
    records: list[FileRecord],
    destination: Path,
    passphrase: str,
) -> None:
    """
    Pipe: path list -> tar -> zstd -> age -> destination
    """

    with destination.open("wb") as outfile:

        # tar

        tar = subprocess.Popen(
            [
                "tar",
                "-cf", "-",
                "-C", str(root),
                "--null",
                "--files-from=-",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        assert tar.stdin is not None
        assert tar.stdout is not None

        # zstd

        zstd = subprocess.Popen(
            [
                "zstd",
                "-q",
                "-c",
            ],
            stdin=tar.stdout,
            stdout=subprocess.PIPE,
        )

        tar.stdout.close()

        assert zstd.stdout is not None

        # age

        age = age_encrypt_process(
            stdin=zstd.stdout,
            stdout=outfile,
            passphrase=passphrase,
        )

        zstd.stdout.close()

        try:
            for record in records:
                tar.stdin.write(os.fsencode(record.path))
                tar.stdin.write(b"\0")

            tar.stdin.close()

            tar_rc = tar.wait()
            zstd_rc = zstd.wait()
            age_rc = age.wait()

        except BaseException:
            for proc in (tar, zstd, age):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

            destination.unlink(missing_ok=True)
            raise

    if tar_rc != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"tar failed with exit status {tar_rc}")

    if zstd_rc != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"zstd failed with exit status {zstd_rc}")

    if age_rc != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"age failed with exit status {age_rc}")


def atomic_replace(temp: Path, final: Path) -> None:
    os.replace(temp, final)


def create_pack(
    root: Path,
    destination: Path,
    pack_id: str,
    passphrase: str,
) -> None:
    root = root.resolve()
    destination.mkdir(parents=True, exist_ok=True)

    records = scan(root, pack_id)

    archive_final = destination / f"coldpack-{pack_id}.tar.zst.age"
    manifest_final = destination / f"coldpack-{pack_id}.jsonl.age"

    archive_tmp = destination / f".coldpack-{pack_id}.tar.zst.age.tmp"
    manifest_plain_tmp = destination / f".coldpack-{pack_id}.jsonl.tmp"
    manifest_encrypted_tmp = destination / f".coldpack-{pack_id}.jsonl.age.tmp"

    if archive_final.exists() or manifest_final.exists():
        raise RuntimeError(f"pack already exists: {pack_id}")

    try:
        create_archive(
            root,
            records,
            archive_tmp,
            passphrase,
        )

        write_manifest(
            manifest_plain_tmp,
            pack_id,
            records,
        )

        encrypt_file(
            manifest_plain_tmp,
            manifest_encrypted_tmp,
            passphrase,
        )

        # Publish only after both artifacts exist successfully.
        atomic_replace(archive_tmp, archive_final)
        atomic_replace(manifest_encrypted_tmp, manifest_final)

    finally:
        archive_tmp.unlink(missing_ok=True)
        manifest_plain_tmp.unlink(missing_ok=True)
        manifest_encrypted_tmp.unlink(missing_ok=True)


def prompt_passphrase() -> str:
    password = getpass.getpass("Coldpack passphrase: ")

    if not password:
        raise SystemExit("empty passphrase refused")

    confirm = getpass.getpass("Confirm passphrase: ")

    if password != confirm:
        raise SystemExit("passphrases do not match")

    return password


def main() -> None:
    require_tools()

    if len(sys.argv) != 4:
        print(
            f"usage: {sys.argv[0]} ROOT DEST PACK_ID",
            file=sys.stderr,
        )
        raise SystemExit(2)

    root = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    pack_id = sys.argv[3]

    passphrase = prompt_passphrase()

    create_pack(
        root,
        destination,
        pack_id,
        passphrase,
    )

if __name__ == "__main__":
    main()
