#!/usr/bin/env python3
# WHY: Checks Maven's emitted class evidence using JSON fields, avoiding brittle text matching.

import json
import pathlib
import sys


def main() -> None:
    report_path = pathlib.Path(sys.argv[1])
    production_output = pathlib.Path(sys.argv[2])
    with report_path.open(encoding="utf-8") as report_file:
        report = json.load(report_file)

    if report["staticEvidenceAvailable"] is not True:
        raise AssertionError("static application bytecode evidence is unavailable")
    if pathlib.Path(report["productionOutput"]).resolve() != production_output.resolve():
        raise AssertionError("report does not identify the copied baseline production output")
    if not production_output.is_dir() or not any(production_output.rglob("*.class")):
        raise AssertionError("copied baseline production output is missing class files")

    groups = report["groups"]
    runtime_only = groups["runtimeObservedWithoutApplicationReference"]
    application_referenced = groups["applicationReferenced"]
    neither = groups["neitherReferencedNorObserved"]
    observed_mail_classes = [
        class_name
        for class_name in report["runtimeObservedClasses"]
        if class_name.startswith(("jakarta.mail.", "org.eclipse.angus.mail."))
    ]
    runtime_only_mail_classes = [
        class_name
        for class_name in runtime_only
        if class_name.startswith(("jakarta.mail.", "org.eclipse.angus.mail."))
    ]
    if not observed_mail_classes:
        raise AssertionError("the runtime trace did not observe any Jakarta Mail or Angus Mail classes")
    if not set(observed_mail_classes).issubset(runtime_only_mail_classes):
        raise AssertionError("not every observed mail class was classified as runtime-only")
    application_mail_classes = [
        class_name
        for class_name in application_referenced
        if class_name.startswith(("jakarta.mail.", "org.eclipse.angus.mail."))
    ]
    if application_mail_classes:
        raise AssertionError(
            f"mail classes were classified as application-referenced: {application_mail_classes}"
        )
    if "org.apache.commons.codec.binary.Hex" not in neither:
        raise AssertionError("unused Commons Codec Hex class was not classified as neither observed nor referenced")


if __name__ == "__main__":
    main()
