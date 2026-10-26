#!/usr/bin/env python3
# WHY: Confirms Spring Boot embeds a smaller, class-trimmed Spring MVC dependency after elision.

from __future__ import annotations

import io
import pathlib
import re
import sys
import zipfile


SPRING_WEBMVC = re.compile(r"BOOT-INF/lib/spring-webmvc-[^/]+\.jar")
CONFIGURED_PASSTHROUGH_ARCHIVE_NAMES = {
    "groovy-templates-4.0.23.jar",
    "micrometer-commons-1.13.6.jar",
    "micrometer-observation-1.13.6.jar",
    "spring-aop-6.1.14.jar",
    "spring-beans-6.1.14.jar",
    "spring-boot-3.3.5.jar",
    "spring-boot-autoconfigure-3.3.5.jar",
    "spring-context-6.1.14.jar",
    "spring-context-support-6.1.14.jar",
    "spring-expression-6.1.14.jar",
    "spring-web-6.1.14.jar",
}
AUTOMATIC_PASSTHROUGH_ARCHIVE_NAMES = {
    "angus-activation-2.0.2.jar",
    "jackson-annotations-2.18.2.jar",
    "jackson-core-2.18.2.jar",
    "jakarta.activation-api-2.1.3.jar",
    "jakarta.annotation-api-2.1.1.jar",
    "jakarta.mail-2.0.3.jar",
    "jakarta.servlet.jsp.jstl-api-3.0.2.jar",
    "jakarta.validation-api-3.0.2.jar",
    "log4j-api-2.23.1.jar",
    "log4j-to-slf4j-2.23.1.jar",
    "logback-classic-1.5.11.jar",
    "logback-core-1.5.11.jar",
    "reactor-core-3.6.11.jar",
    "spring-core-6.1.14.jar",
    "tomcat-embed-core-10.1.31.jar",
    "tomcat-embed-el-10.1.31.jar",
    "tomcat-embed-websocket-10.1.31.jar",
}
PASSTHROUGH_ARCHIVE_NAMES = (
    CONFIGURED_PASSTHROUGH_ARCHIVE_NAMES | AUTOMATIC_PASSTHROUGH_ARCHIVE_NAMES
)
DISPATCHER_SERVLET = "org/springframework/web/servlet/DispatcherServlet.class"


def nested_webmvc(archive_path: pathlib.Path) -> tuple[str, bytes]:
    with zipfile.ZipFile(archive_path) as archive:
        names = [name for name in archive.namelist() if SPRING_WEBMVC.fullmatch(name)]
        if len(names) != 1:
            raise AssertionError(
                f"expected exactly one nested Spring MVC JAR in {archive_path}, found {names}"
            )
        return names[0], archive.read(names[0])


def has_unsupported_layout(content: bytes) -> bool:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = archive.namelist()
        return "module-info.class" in names or any(
            name.startswith("META-INF/versions/")
            and name.endswith(".class")
            and not name.endswith("/module-info.class")
            for name in names
        )


def nested_passthrough_archives(
    archive_path: pathlib.Path, *, reject_unknown_automatic: bool = True
) -> dict[str, bytes]:
    with zipfile.ZipFile(archive_path) as archive:
        names = []
        for path in archive.namelist():
            name = pathlib.PurePosixPath(path).name
            if not path.startswith("BOOT-INF/lib/") or not path.endswith(".jar"):
                continue
            content = archive.read(path)
            unsupported = has_unsupported_layout(content)
            if name in CONFIGURED_PASSTHROUGH_ARCHIVE_NAMES:
                names.append(path)
            elif unsupported:
                if name not in AUTOMATIC_PASSTHROUGH_ARCHIVE_NAMES:
                    if reject_unknown_automatic:
                        raise AssertionError(
                            f"unknown automatic pass-through JAR appeared: {name}"
                        )
                    continue
                names.append(path)
        if not names:
            raise AssertionError(f"no pass-through JARs in {archive_path}")
        return {pathlib.PurePosixPath(name).name: archive.read(name) for name in names}


def classes(content: bytes) -> set[str]:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return {name for name in archive.namelist() if name.endswith(".class")}


def capture(archive_path: pathlib.Path, output_path: pathlib.Path) -> None:
    _, content = nested_webmvc(archive_path)
    output_path.write_bytes(content)


def compare(archive_path: pathlib.Path, baseline_path: pathlib.Path) -> None:
    entry_name, trimmed = nested_webmvc(archive_path)
    baseline = baseline_path.read_bytes()
    baseline_classes = classes(baseline)
    trimmed_classes = classes(trimmed)
    if len(trimmed) >= len(baseline):
        raise AssertionError(
            f"nested Spring MVC JAR did not shrink: {len(baseline)} to {len(trimmed)} bytes"
        )
    if not trimmed_classes < baseline_classes:
        raise AssertionError("nested Spring MVC JAR did not lose any class entries")
    if DISPATCHER_SERVLET not in trimmed_classes:
        raise AssertionError(f"trimmed {entry_name} lost DispatcherServlet")
    print(
        f"{entry_name} shrank from {len(baseline)} to {len(trimmed)} bytes and "
        f"from {len(baseline_classes)} to {len(trimmed_classes)} classes"
    )


def capture_skip(archive_path: pathlib.Path, output_path: pathlib.Path) -> None:
    output_path.mkdir(parents=True, exist_ok=True)
    for name, content in nested_passthrough_archives(
        archive_path, reject_unknown_automatic=False
    ).items():
        (output_path / name).write_bytes(content)


def compare_skip(archive_path: pathlib.Path, baseline_path: pathlib.Path) -> None:
    current = nested_passthrough_archives(archive_path)
    current_names = set(current)
    missing_configured = CONFIGURED_PASSTHROUGH_ARCHIVE_NAMES - current_names
    if missing_configured:
        raise AssertionError(
            f"configured pass-through JARs were not packaged: {sorted(missing_configured)}"
        )
    unexpected = current_names - PASSTHROUGH_ARCHIVE_NAMES
    if unexpected:
        raise AssertionError(
            f"unknown pass-through nested JARs appeared: {sorted(unexpected)}"
        )
    for name, content in current.items():
        original_path = baseline_path / name
        if not original_path.is_file():
            raise AssertionError(f"baseline is missing pass-through JAR {name}")
        if content != original_path.read_bytes():
            raise AssertionError(f"pass-through {name} was modified")
    configured_count = len(CONFIGURED_PASSTHROUGH_ARCHIVE_NAMES & current_names)
    automatic_count = len(AUTOMATIC_PASSTHROUGH_ARCHIVE_NAMES & current_names)
    print(
        f"{configured_count} configured and {automatic_count} automatic pass-through JAR(s) "
        "remained byte-identical"
    )


def main() -> None:
    mode, archive_path, output_path = sys.argv[1:]
    if mode == "capture":
        capture(pathlib.Path(archive_path), pathlib.Path(output_path))
    elif mode == "compare":
        compare(pathlib.Path(archive_path), pathlib.Path(output_path))
    elif mode == "capture-skip":
        capture_skip(pathlib.Path(archive_path), pathlib.Path(output_path))
    elif mode == "compare-skip":
        compare_skip(pathlib.Path(archive_path), pathlib.Path(output_path))
    else:
        raise ValueError(f"unsupported verification mode: {mode}")


if __name__ == "__main__":
    main()
