import ctypes
import os
import shutil
import sys
import tarfile
import tempfile
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path


ARCHIVES = {
    "20030228_easy_ham.tar.bz2": "easy_ham",
    "20030228_spam.tar.bz2": "spam",
}
DOWNLOADS_FOLDER_ID = uuid.UUID("374DE290-123F-4565-9164-39C4925E467B")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def get_downloads_folder() -> Path:
    if not hasattr(ctypes, "windll"):
        raise OSError("This script must run on Windows to resolve Downloads.")

    folder_id = GUID.from_buffer_copy(DOWNLOADS_FOLDER_ID.bytes_le)
    path_pointer = ctypes.c_wchar_p()
    result = ctypes.windll.shell32.SHGetKnownFolderPath(
        ctypes.byref(folder_id), 0, None, ctypes.byref(path_pointer)
    )
    if result != 0:
        raise OSError(result, "Could not resolve the current user's Downloads folder.")
    try:
        return Path(path_pointer.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(path_pointer)


def validate_archive(archive: tarfile.TarFile, expected_root: str) -> int:
    members = archive.getmembers()
    if not members:
        raise ValueError(f"Archive for {expected_root} is empty.")

    entries: dict[tuple[str, ...], str] = {}
    for member in members:
        if "\\" in member.name:
            raise ValueError(f"Archive contains a Windows-style path: {member.name!r}")

        name = member.name.rstrip("/")
        parts = tuple(name.split("/"))
        if (
            not name
            or name.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or parts[0] != expected_root
        ):
            raise ValueError(f"Archive contains an unexpected or unsafe path: {member.name!r}")

        if any(
            any(character in part for character in '<>:"|?*')
            or part.endswith((" ", "."))
            for part in parts
        ):
            raise ValueError(f"Archive contains a Windows-unsafe path: {member.name!r}")

        if member.isdir():
            kind = "directory"
        elif member.isfile():
            kind = "file"
        else:
            raise ValueError(f"Archive contains an unsupported entry: {member.name!r}")

        if parts in entries:
            raise ValueError(f"Archive contains a duplicate path: {member.name!r}")
        entries[parts] = kind

        for index in range(1, len(parts)):
            parent = parts[:index]
            if entries.get(parent) == "file":
                raise ValueError(f"Archive file is also used as a directory: {member.name!r}")

    if entries.get((expected_root,)) != "directory":
        raise ValueError(f"Archive is missing its expected {expected_root!r} folder.")

    for parts in entries:
        if entries.get(parts) == "file":
            for index in range(1, len(parts)):
                if entries.get(parts[:index]) == "file":
                    raise ValueError(f"Archive file is also used as a directory: {'/'.join(parts)!r}")

    return sum(member.isfile() for member in members)


def extract_archive(archive_path: Path, expected_root: str, staging: Path) -> int:
    with tarfile.open(archive_path, mode="r:bz2") as archive:
        expected_files = validate_archive(archive, expected_root)
        for member in archive.getmembers():
            parts = tuple(member.name.rstrip("/").split("/"))
            destination = staging.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise tarfile.ExtractError(f"Could not read archive member {member.name!r}.")
            with source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)

    return expected_files


def email_body(message) -> str:
    part = message.get_body(preferencelist=("plain",))
    if part is None:
        part = message.get_body(preferencelist=("html",))
    if part is None and message.get_content_maintype() == "text":
        part = message
    if part is None:
        return ""

    try:
        content = part.get_content()
    except (LookupError, UnicodeError):
        payload = part.get_payload(decode=True)
        content = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload else ""
    if isinstance(content, bytes):
        return content.decode(part.get_content_charset() or "utf-8", errors="replace")
    return str(content)


def show_sample(folder: Path, label: str) -> None:
    email_files = sorted(path for path in folder.rglob("*") if path.is_file())
    if not email_files:
        raise ValueError(f"No email files were found in {folder}.")

    message = BytesParser(policy=policy.default).parsebytes(email_files[0].read_bytes())
    preview = " ".join(email_body(message).split())
    if len(preview) > 240:
        preview = preview[:237] + "..."

    print(f"\nSample from {label}: {email_files[0].relative_to(folder)}")
    print(f"Subject: {message.get('Subject', '(no subject)')}")
    print(f"From: {message.get('From', '(no sender)')}")
    print(f"Body preview: {preview or '(no text/plain or text/html body)'}")


def main() -> int:
    try:
        downloads = get_downloads_folder()
        project = Path.cwd()
        dataset = project / "dataset"
        archive_paths = {name: downloads / name for name in ARCHIVES}

        missing = [str(path) for path in archive_paths.values() if not path.is_file()]
        if missing:
            raise FileNotFoundError("Required archive(s) not found: " + ", ".join(missing))

        if dataset.is_symlink():
            raise ValueError(f"Dataset destination must not be a symbolic link: {dataset}")
        if dataset.exists() and not dataset.is_dir():
            raise NotADirectoryError(f"Dataset destination is not a directory: {dataset}")
        dataset.mkdir(exist_ok=True)

        destinations = [dataset / root for root in ARCHIVES.values()]
        conflicts = [str(path) for path in destinations if path.exists() or path.is_symlink()]
        if conflicts:
            raise FileExistsError(
                "Refusing to overwrite existing extraction path(s): " + ", ".join(conflicts)
            )

        for archive_name, root in ARCHIVES.items():
            with tarfile.open(archive_paths[archive_name], mode="r:bz2") as archive:
                validate_archive(archive, root)

        counts: dict[str, int] = {}
        with tempfile.TemporaryDirectory(prefix=".spamassassin-stage-", dir=dataset) as temporary:
            staging = Path(temporary)
            for archive_name, root in ARCHIVES.items():
                counts[root] = extract_archive(archive_paths[archive_name], root, staging)

            for root in ARCHIVES.values():
                source = staging / root
                if not source.is_dir():
                    raise ValueError(f"Expected extracted folder was not created: {source}")

            for root in ARCHIVES.values():
                os.rename(staging / root, dataset / root)

        for root in ARCHIVES.values():
            actual_count = sum(path.is_file() for path in (dataset / root).rglob("*"))
            if actual_count != counts[root]:
                raise OSError(
                    f"Extracted file count mismatch for {root}: "
                    f"expected {counts[root]}, found {actual_count}."
                )
            print(f"{root}: {actual_count} email files")

        show_sample(dataset / "easy_ham", "easy_ham")
        show_sample(dataset / "spam", "spam")
        print(f"\nExtraction complete. Dataset location: {dataset}")
        print("The original downloaded archives were left unchanged.")
        return 0
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
