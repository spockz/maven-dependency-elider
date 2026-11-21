#!/usr/bin/env bash
# WHY: Exercises the same policy against isolated benign compiler outputs and real Maven publications.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
evidence=$1/forbidden-code
maven=$2
shift 2
maven_options=("$@")
java="${JAVA_HOME:?JAVA_HOME must point to a JDK 21+ installation}/bin/java"
javac="$JAVA_HOME/bin/javac"
pom="$repo_root/examples/example-forbidden-code-app/pom.xml"
plugin=io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT
mkdir -- "$evidence"
cd -- "$repo_root"

expect_maven() {
  local expected=$1 log=$2 code=0
  shift 2
  "$maven" "${maven_options[@]}" "$@" >"$log" 2>&1 || code=$?
  if [[ $code != "$expected" ]]; then
    printf 'Expected Maven exit %s, got %s. Full output follows.\n' "$expected" "$code" >&2
    cat -- "$log" >&2
    return 1
  fi
}

prepare_case() {
  local name=$1 variant=$2 version=$3
  shift 3
  case_dir="$evidence/$name"
  mkdir -- "$case_dir"
  fixture=(
    -f "$pom"
    "-Dexample.variant=$variant"
    "-Dcommons-compress.version=$version"
    "-Dexample.buildDirectory=$case_dir/build"
    -Dmaven.build.cache.enabled=false
    "$@"
  )
  expect_maven 0 "$case_dir/compile.log" "${fixture[@]}" clean compile dependency:build-classpath \
    "-Dmdep.outputFile=$case_dir/classpath"
  timeout 30s "$java" "-Xlog:class+load=info:file=$case_dir/trace.log" \
    --class-path "$case_dir/build/classes:$(<"$case_dir/classpath")" \
    "io.github.spockz.example.forbidden.${variant}Application" >"$case_dir/application.log"
  if [[ $(<"$case_dir/application.log") != 'message.txt: hello' ]]; then
    cat -- "$case_dir/application.log" >&2
    return 1
  fi
  policy=(
    "-Delide.traceFiles=$case_dir/trace.log"
    "-Delide.cveCacheDirectory=$case_dir/advisories"
  )
}

analyze() {
  expect_maven "$1" "$case_dir/analyze.log" --offline "${fixture[@]}" "${policy[@]}" \
    "-Delide.reportFile=$case_dir/analysis-classes.json" -Delide.productionClassesComplete=true \
    "-Delide.trimJars=$2" "-Delide.failOnForbiddenCode=$3" "$plugin:analyze"
}

apply_policy() {
  local expected=$1 trim=$2 enforce=$3 log=$4
  shift 4
  expect_maven "$expected" "$case_dir/$log" --offline "${fixture[@]}" "${policy[@]}" \
    -Pelide-forbidden-example "-Delide.trimJars=$trim" "-Delide.failOnForbiddenCode=$enforce" \
    "$@" process-classes
}

replay() {
  local snapshot=$1 original_log=$2 replay_log=$3
  expect_maven 0 "$case_dir/$replay_log" --offline "${fixture[@]}" \
    "-Delide.summaryFile=$case_dir/build/$snapshot" -Delide.failOnForbiddenCode=true "$plugin:report"
  local policy_rows='^\[INFO\] (Forbidden code (overall:|PREDICTED |OBSERVED )|    (scope|provider)=)'
  grep -E "$policy_rows" "$case_dir/$original_log" \
    >"$case_dir/expected-policy.log"
  grep -E "$policy_rows" "$case_dir/$replay_log" \
    >"$case_dir/replayed-policy.log"
  diff -u "$case_dir/expected-policy.log" "$case_dir/replayed-policy.log"
}

# Compile this case first so a missing example fails on its real Maven entry point.
prepare_case safe Plain 1.17

classpath_file="$evidence/verification-classpath"
expect_maven 0 "$evidence/verification-setup.log" -f "$repo_root/dependency-elider-maven-plugin/pom.xml" \
  dependency:build-classpath -DincludeScope=test "-Dmdep.outputFile=$classpath_file"
mkdir -- "$evidence/checks"
verification_classpath=$(<"$classpath_file")
"$javac" -proc:none --class-path "$verification_classpath" -d "$evidence/checks" \
  "$repo_root/examples/support/ForbiddenCodeExampleChecks.java"

verify_case() {
  "$java" --class-path "$evidence/checks:$verification_classpath" ForbiddenCodeExampleChecks \
    "$case_dir" "$@"
}

safe_dir=$case_dir
analyze 0 true true
apply_policy 0 true true elide.log
verify_case PASS PASS 1.17 true true
replay dependency-elider-analysis-report.json analyze.log replay-analysis.log
replay dependency-elider-report.json elide.log replay.log

prepare_case decode Decode 1.17
analyze 1 true true
grep -F 'Forbidden code PREDICTED VIOLATION: CVE-2026-114938' "$case_dir/analyze.log"
apply_policy 1 true true rejected.log
grep -F 'Forbidden code OBSERVED VIOLATION: CVE-2026-114938' "$case_dir/rejected.log"
test ! -e "$case_dir/build/dependency-elider-report.json"
test ! -e "$case_dir/build/dependency-elider.openvex.json"
test ! -e "$case_dir/build/dependency-elider-class-usage.json"
test ! -e "$case_dir/build/dependency-elider-sbom.cdx.json"
apply_policy 0 true false elide.log
verify_case PASS PASS 1.17 true false
replay dependency-elider-analysis-report.json analyze.log replay-analysis.log
replay dependency-elider-report.json elide.log replay.log

prepare_case retained Stream 1.17
analyze 1 true true
grep -F 'Forbidden code PREDICTED VIOLATION: CVE-2018-11771' "$case_dir/analyze.log"
summary="$safe_dir/build/dependency-elider-report.json"
vex="$safe_dir/build/dependency-elider.openvex.json"
cp -- "$summary" "$case_dir/previous-report.json"
cp -- "$vex" "$case_dir/previous-vex.json"
apply_policy 1 true true rejected.log "-Delide.summaryFile=$summary" "-Delide.vexFile=$vex"
grep -F 'Forbidden code OBSERVED VIOLATION: CVE-2018-11771 org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int)' "$case_dir/rejected.log"
cmp -- "$summary" "$case_dir/previous-report.json"
cmp -- "$vex" "$case_dir/previous-vex.json"
test ! -e "$case_dir/build/dependency-elider-class-usage.json"
test ! -e "$case_dir/build/dependency-elider-sbom.cdx.json"
test ! -e "$case_dir/build/elided-artifacts/.trim-analysis-cache.json"
apply_policy 0 true false elide.log
verify_case VIOLATION VIOLATION 1.17 true false
replay dependency-elider-report.json elide.log replay.log

prepare_case untrimmed Plain 1.17
analyze 0 true false
apply_policy 0 false false elide.log
verify_case PASS VIOLATION 1.17 false false
replay dependency-elider-analysis-report.json analyze.log replay-analysis.log
replay dependency-elider-report.json elide.log replay.log

prepare_case fixed Plain 1.18 -Dmaven.compiler.release=17 \
  "-Delide.runtimeInputs=$evidence/fixed/missing-runtime"
analyze 0 false true
apply_policy 0 false true elide.log
verify_case NOT_APPLICABLE NOT_APPLICABLE 1.18 true true 17
replay dependency-elider-report.json elide.log replay.log

prepare_case decode-without-runtime Decode 1.18 -Dmaven.compiler.release=17 \
  "-Delide.runtimeInputs=$evidence/decode-without-runtime/missing-runtime"
analyze 1 false true
grep -F 'Runtime input does not exist' "$case_dir/analyze.log"
apply_policy 1 false true rejected.log
grep -F 'Forbidden code OBSERVED VIOLATION: CVE-2026-114938' "$case_dir/rejected.log"
test ! -e "$case_dir/build/dependency-elider-report.json"
test ! -e "$case_dir/build/dependency-elider.openvex.json"
apply_policy 0 false false elide.log
verify_case NOT_APPLICABLE NOT_APPLICABLE 1.18 true false 17
replay dependency-elider-analysis-report.json analyze.log replay-analysis.log
replay dependency-elider-report.json elide.log replay.log

printf 'Forbidden-code example checks passed.\n'
