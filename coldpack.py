import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

CHUNK_SIZE = 1024 * 1024


class ManifestDecryptionError(RuntimeError):
    pass


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

    @classmethod
    def from_dict(cls, value: dict) -> "FileRecord":
        try:
            hash_algo, hash_value = value["hash"].split(":", 1)
            return cls(
                path=value["path"],
                hash_algo=hash_algo,
                hash=hash_value,
                size=value["size"],
                mtime_ns=value["mtime_ns"],
                pack=value["pack"],
            )
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise RuntimeError("invalid file record in manifest") from error


def require_tools(*tools: str) -> None:
    if not tools:
        tools = ("tar", "zstd", "age", "age-plugin-batchpass")

    for tool in tools:
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


def age_decrypt_process(
    *,
    stdin,
    stdout,
    passphrase: str,
) -> subprocess.Popen:
    """Start ``age -d -j batchpass`` with a private passphrase pipe."""
    rfd, _ = make_passphrase_pipe(passphrase)

    env = os.environ.copy()
    env["AGE_PASSPHRASE_FD"] = str(rfd)

    try:
        proc = subprocess.Popen(
            [
                "age",
                "-d",
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


def next_pack_version(destination: Path, pack_id: str) -> int:
    """Return the next numeric version for a pack ID."""
    if not pack_id or pack_id in (".", ".."):
        raise RuntimeError("pack ID must not be empty, '.' or '..'")

    if "/" in pack_id or "\\" in pack_id:
        raise RuntimeError("pack ID must not contain path separators")

    pattern = re.compile(
        rf"coldpack-{re.escape(pack_id)}-(\d+)"
        rf"(?:\.tar\.zst|\.jsonl)\.age"
    )
    versions = []

    for path in destination.iterdir():
        match = pattern.fullmatch(path.name)

        if match is not None:
            versions.append(int(match.group(1)))

    return max(versions, default=-1) + 1


def latest_manifest(destination: Path, pack_id: str) -> tuple[Path, str] | None:
    """Return the latest manifest path and full pack ID for a series."""
    pattern = re.compile(
        rf"coldpack-({re.escape(pack_id)}-(\d+))\.jsonl\.age"
    )
    matches = []

    for path in destination.iterdir():
        match = pattern.fullmatch(path.name)

        if match is not None:
            matches.append((int(match.group(2)), path.name, path, match.group(1)))

    if not matches:
        return None

    _, _, path, pack_id = max(matches)
    return path, pack_id


def read_manifest(
    path: Path,
    expected_pack_id: str,
    passphrase: str,
) -> list[FileRecord]:
    """Decrypt and parse a cumulative pack manifest."""
    with path.open("rb") as infile:
        age = age_decrypt_process(
            stdin=infile,
            stdout=subprocess.PIPE,
            passphrase=passphrase,
        )
        plaintext, _ = age.communicate()

    if age.returncode != 0:
        raise ManifestDecryptionError(
            f"age failed with exit status {age.returncode}"
        )

    try:
        lines = plaintext.decode("utf-8").splitlines()
        header = json.loads(lines[0])
    except (IndexError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid manifest: {path}") from error

    if header != {"type": "pack", "version": 1, "pack": expected_pack_id}:
        raise RuntimeError(f"invalid manifest header: {path}")

    records = []

    for line_number, line in enumerate(lines[1:], start=2):
        try:
            value = json.loads(line)
            records.append(FileRecord.from_dict(value))
        except (json.JSONDecodeError, RuntimeError) as error:
            raise RuntimeError(
                f"invalid manifest record at {path}:{line_number}"
            ) from error

    return records


def create_pack(
    root: Path,
    destination: Path,
    pack_id: str,
    passphrase: str,
) -> str:
    root = root.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    pack_version = next_pack_version(destination, pack_id)
    full_pack_id = f"{pack_id}-{pack_version:03d}"

    previous_manifest = latest_manifest(destination, pack_id)

    if previous_manifest is None:
        previous_records = []
    else:
        manifest_path, manifest_pack_id = previous_manifest
        try:
            previous_records = read_manifest(
                manifest_path,
                manifest_pack_id,
                passphrase,
            )
        except ManifestDecryptionError as error:
            raise RuntimeError(
                "passphrase does not match the previous pack version "
                f"{manifest_pack_id} (or its manifest is damaged)"
            ) from error

    observed_records = scan(root, full_pack_id)
    witnessed = {
        (record.path, record.hash_algo, record.hash)
        for record in previous_records
    }
    new_records = [
        record
        for record in observed_records
        if (record.path, record.hash_algo, record.hash) not in witnessed
    ]
    cumulative_records = previous_records + new_records

    archive_final = destination / f"coldpack-{full_pack_id}.tar.zst.age"
    manifest_final = destination / f"coldpack-{full_pack_id}.jsonl.age"

    archive_tmp = destination / f".coldpack-{full_pack_id}.tar.zst.age.tmp"
    manifest_plain_tmp = destination / f".coldpack-{full_pack_id}.jsonl.tmp"
    manifest_encrypted_tmp = destination / f".coldpack-{full_pack_id}.jsonl.age.tmp"

    if archive_final.exists() or manifest_final.exists():
        raise RuntimeError(f"pack already exists: {full_pack_id}")

    try:
        create_archive(
            root,
            new_records,
            archive_tmp,
            passphrase,
        )

        write_manifest(
            manifest_plain_tmp,
            full_pack_id,
            cumulative_records,
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

    return full_pack_id


def extract_pack(
    archive: Path,
    destination: Path,
    passphrase: str,
) -> None:
    """Pipe an encrypted coldpack archive through age and zstd into tar."""
    if not archive.is_file():
        raise RuntimeError(f"archive not found: {archive}")

    destination_existed = destination.exists()

    if destination_existed and not destination.is_dir():
        raise RuntimeError(f"destination is not a directory: {destination}")

    destination.mkdir(parents=True, exist_ok=True)

    with archive.open("rb") as infile:
        age = age_decrypt_process(
            stdin=infile,
            stdout=subprocess.PIPE,
            passphrase=passphrase,
        )

        assert age.stdout is not None

        zstd = subprocess.Popen(
            ["zstd", "-q", "-d", "-c"],
            stdin=age.stdout,
            stdout=subprocess.PIPE,
        )
        age.stdout.close()

        assert zstd.stdout is not None

        tar = subprocess.Popen(
            ["tar", "-xf", "-", "-C", str(destination)],
            stdin=zstd.stdout,
        )
        zstd.stdout.close()

        try:
            tar_rc = tar.wait()
            zstd_rc = zstd.wait()
            age_rc = age.wait()
        except BaseException:
            for proc in (age, zstd, tar):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            raise

    if age_rc != 0:
        error = RuntimeError(f"age failed with exit status {age_rc}")
    elif zstd_rc != 0:
        error = RuntimeError(f"zstd failed with exit status {zstd_rc}")
    elif tar_rc != 0:
        error = RuntimeError(f"tar failed with exit status {tar_rc}")
    else:
        return

    if not destination_existed:
        shutil.rmtree(destination)

    raise error


def decrypt_manifest(
    manifest: Path,
    passphrase: str,
    *,
    stdout=None,
) -> None:
    """Decrypt an encrypted JSON Lines manifest to stdout."""
    if not manifest.is_file():
        raise RuntimeError(f"manifest not found: {manifest}")

    if stdout is None:
        stdout = sys.stdout.buffer

    with manifest.open("rb") as infile:
        age = age_decrypt_process(
            stdin=infile,
            stdout=stdout,
            passphrase=passphrase,
        )
        age_rc = age.wait()

    if age_rc != 0:
        raise RuntimeError(f"age failed with exit status {age_rc}")


def prompt_passphrase(*, confirm: bool) -> str:
    password = getpass.getpass("Coldpack passphrase: ")

    if not password:
        raise SystemExit("empty passphrase refused")

    if not confirm:
        return password

    confirmation = getpass.getpass("Confirm passphrase: ")

    if password != confirmation:
        raise SystemExit("passphrases do not match")

    return password


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create and extract encrypted archives for cold files."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    pack = commands.add_parser("pack", help="create an encrypted archive")
    pack.add_argument("root", type=Path, help="directory to archive")
    pack.add_argument("destination", type=Path, help="directory for pack files")
    pack.add_argument(
        "pack_id",
        help="series ID; the next numeric pack version is selected automatically",
    )

    extract = commands.add_parser("extract", help="extract an encrypted archive")
    extract.add_argument("archive", type=Path, help="encrypted .tar.zst.age file")
    extract.add_argument("destination", type=Path, help="directory to extract into")

    manifest = commands.add_parser(
        "manifest",
        help="decrypt a pack manifest to standard output",
    )
    manifest.add_argument("manifest", type=Path, help="encrypted .jsonl.age file")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.command == "pack":
        require_tools("tar", "zstd", "age", "age-plugin-batchpass")
        pack_id = create_pack(
            args.root,
            args.destination,
            args.pack_id,
            prompt_passphrase(confirm=True),
        )
        print(f"created pack {pack_id}", file=sys.stderr)
    elif args.command == "extract":
        require_tools("tar", "zstd", "age", "age-plugin-batchpass")
        extract_pack(
            args.archive,
            args.destination,
            prompt_passphrase(confirm=False),
        )
    else:
        require_tools("age", "age-plugin-batchpass")
        decrypt_manifest(
            args.manifest,
            prompt_passphrase(confirm=False),
        )

if __name__ == "__main__":
    main()
