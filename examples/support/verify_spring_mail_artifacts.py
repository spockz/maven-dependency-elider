#!/usr/bin/env python3
# WHY: Proves elision preserves the exact Spring mail runtime JARs from the baseline package.

import hashlib
import pathlib
import re
import sys
import zipfile


MAIL_ARTIFACT_PATTERNS = {
    "spring-context-support": re.compile(r"BOOT-INF/lib/spring-context-support-[^/]+\.jar"),
    "jakarta.mail": re.compile(r"BOOT-INF/lib/jakarta\.mail-[^/]+\.jar"),
    "jakarta.activation-api": re.compile(r"BOOT-INF/lib/jakarta\.activation-api-[^/]+\.jar"),
    "angus-activation": re.compile(r"BOOT-INF/lib/angus-activation-[^/]+\.jar"),
}


def mail_entries(archive_path: pathlib.Path) -> dict[str, bytes]:
    with zipfile.ZipFile(archive_path) as archive:
        matches = {
            entry_name: archive.read(entry_name)
            for entry_name in archive.namelist()
            if any(pattern.fullmatch(entry_name) for pattern in MAIL_ARTIFACT_PATTERNS.values())
        }

    for artifact_name, pattern in MAIL_ARTIFACT_PATTERNS.items():
        artifact_entries = [name for name in matches if pattern.fullmatch(name)]
        if len(artifact_entries) != 1:
            raise AssertionError(
                f"expected exactly one nested {artifact_name} JAR in {archive_path}, found {artifact_entries}"
            )
    return matches


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def capture(archive_path: pathlib.Path, baseline_dir: pathlib.Path) -> None:
    baseline_dir.mkdir(parents=True, exist_ok=True)
    entries = mail_entries(archive_path)
    for entry_name, content in entries.items():
        file_path = baseline_dir / pathlib.PurePosixPath(entry_name).name
        file_path.write_bytes(content)
    manifest = {entry_name: digest(content) for entry_name, content in entries.items()}
    (baseline_dir / "sha256.txt").write_text(
        "".join(f"{entry_name} {sha256}\n" for entry_name, sha256 in sorted(manifest.items())),
        encoding="utf-8",
    )


def compare(archive_path: pathlib.Path, baseline_dir: pathlib.Path) -> None:
    entries = mail_entries(archive_path)
    baseline_digests = {
        entry_name: sha256
        for entry_name, sha256 in (
            line.split(" ", maxsplit=1)
            for line in (baseline_dir / "sha256.txt").read_text(encoding="utf-8").splitlines()
        )
    }
    final_digests = {entry_name: digest(content) for entry_name, content in entries.items()}
    if baseline_digests != final_digests:
        raise AssertionError("final Spring mail runtime JAR names or SHA-256 digests differ from baseline")
    for entry_name, content in entries.items():
        baseline_path = baseline_dir / pathlib.PurePosixPath(entry_name).name
        if baseline_path.read_bytes() != content:
            raise AssertionError(f"nested mail JAR bytes changed for {entry_name}")


def main() -> None:
    mode, archive_path, baseline_dir = sys.argv[1:]
    if mode == "capture":
        capture(pathlib.Path(archive_path), pathlib.Path(baseline_dir))
    elif mode == "compare":
        compare(pathlib.Path(archive_path), pathlib.Path(baseline_dir))
    else:
        raise ValueError(f"unsupported verification mode: {mode}")


if __name__ == "__main__":
    main()
