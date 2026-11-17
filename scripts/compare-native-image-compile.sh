#!/usr/bin/env bash
# WHY: Benchmarks GraalVM native-image compile time and binary size with and without elision.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_GRAALVM_HOME="$ROOT_DIR/.scratch/toolchains/graalvm-jdk-21.0.12+7.1"
GRAALVM_HOME="${GRAALVM_HOME:-}"

if [[ -z "$GRAALVM_HOME" ]]; then
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/native-image" ]]; then
    GRAALVM_HOME="$JAVA_HOME"
  elif [[ -x "$DEFAULT_GRAALVM_HOME/bin/native-image" ]]; then
    GRAALVM_HOME="$DEFAULT_GRAALVM_HOME"
  elif command -v native-image >/dev/null 2>&1; then
    GRAALVM_HOME="$(cd "$(dirname "$(command -v native-image)")/.." && pwd)"
  fi
fi

if [[ -z "$GRAALVM_HOME" || ! -x "$GRAALVM_HOME/bin/native-image" ]]; then
  echo "ERROR: Could not locate GraalVM native-image. Set GRAALVM_HOME to a GraalVM JDK." >&2
  exit 1
fi

NATIVE_IMAGE_BIN="$GRAALVM_HOME/bin/native-image"
JAVA_BIN="$GRAALVM_HOME/bin/java"
MAVEN="${MAVEN:-$ROOT_DIR/mvnw}"
FIXTURE_DIR="${FIXTURE_DIR:-$ROOT_DIR/examples/example-basic-app}"
TRIM_JARS="${TRIM_JARS:-true}"
NATIVE_IMAGE_EXTRA_ARGS="${NATIVE_IMAGE_EXTRA_ARGS:-}"

usage() {
  cat <<'EOF'
Usage: scripts/compare-native-image-compile.sh [options]

Options:
  --fixture <dir>     Maven project directory producing an executable shaded JAR
                      (default: examples/example-basic-app)
  --trim              Enable -Delide.trimJars=true during the elided build
  --graalvm <dir>     Path to GraalVM JDK home (default: .scratch/toolchains/graalvm-jdk-21.0.12+7.1)
  -h, --help          Show this help message

Environment variables:
  GRAALVM_HOME, MAVEN, FIXTURE_DIR, TRIM_JARS, NATIVE_IMAGE_EXTRA_ARGS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      FIXTURE_DIR="$2"
      shift 2
      ;;
    --trim)
      TRIM_JARS=true
      shift
      ;;
    --graalvm)
      GRAALVM_HOME="$2"
      NATIVE_IMAGE_BIN="$GRAALVM_HOME/bin/native-image"
      JAVA_BIN="$GRAALVM_HOME/bin/java"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$FIXTURE_DIR/pom.xml" ]]; then
  echo "ERROR: Fixture directory does not contain pom.xml: $FIXTURE_DIR" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_logged() {
  local log_file="$TMP_DIR/step.log"
  if ! "$@" >"$log_file" 2>&1; then
    echo "ERROR: Command failed: $*" >&2
    tail -n 60 "$log_file" >&2
    return 1
  fi
}

now_ns() {
  date +%s%N
}

format_seconds() {
  local start_ns="$1"
  local end_ns="$2"
  local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
  printf '%d.%03d' "$((elapsed_ms / 1000))" "$((elapsed_ms % 1000))"
}

pct_change() {
  local before_ms="$1"
  local after_ms="$2"
  if [[ "$before_ms" -eq 0 ]]; then
    printf 'n/a'
    return
  fi
  local diff_tenths=$(( ((after_ms - before_ms) * 1000) / before_ms ))
  local sign=""
  if [[ "$diff_tenths" -gt 0 ]]; then
    sign="+"
  fi
  local abs_tenths="${diff_tenths#-}"
  if [[ "$diff_tenths" -lt 0 ]]; then
    sign="-"
  fi
  printf '%s%d.%d%%' "$sign" "$((abs_tenths / 10))" "$((abs_tenths % 10))"
}

find_shaded_jar() {
  find "$FIXTURE_DIR/target" -maxdepth 1 -type f -name '*.jar' \
    ! -name 'original-*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -n 1
}

echo "Using GraalVM: $("$NATIVE_IMAGE_BIN" --version | head -n 1)"
echo "Fixture:       $FIXTURE_DIR (trimJars=$TRIM_JARS)"

echo
echo "==> Ensuring dependency-elider-maven-plugin is installed..."
run_logged env JAVA_HOME="$GRAALVM_HOME" "$MAVEN" --batch-mode --no-transfer-progress -T 12 \
  -f "$ROOT_DIR/pom.xml" -pl dependency-elider-maven-plugin -am install \
  -DskipTests -Djacoco.skip=true

echo "==> [1/2] Building WITHOUT elision (-Delide.mode=baseline)..."
t0="$(now_ns)"
run_logged env JAVA_HOME="$GRAALVM_HOME" "$MAVEN" --batch-mode --no-transfer-progress --offline \
  -f "$FIXTURE_DIR/pom.xml" -DskipTests=true -Delide.mode=baseline clean package
t1="$(now_ns)"
baseline_pkg_ns=$((t1 - t0))

baseline_jar="$(find_shaded_jar)"
if [[ -z "$baseline_jar" || ! -f "$baseline_jar" ]]; then
  echo "ERROR: Could not find packaged JAR in $FIXTURE_DIR/target" >&2
  exit 1
fi
baseline_jar_bytes="$(stat -c '%s' "$baseline_jar")"

trace_file="$TMP_DIR/classload.log"
"$JAVA_BIN" "-Xlog:class+load=info:file=${trace_file}" -jar "$baseline_jar" >/dev/null

echo "==> [1/2] Compiling native binary WITHOUT elision..."
baseline_bin="$TMP_DIR/app-baseline"
baseline_ni_json="$TMP_DIR/baseline-ni.json"
t0="$(now_ns)"
# shellcheck disable=SC2086
run_logged env JAVA_HOME="$GRAALVM_HOME" "$NATIVE_IMAGE_BIN" --no-fallback \
  --enable-sbom=cyclonedx,export "-H:BuildOutputJSONFile=${baseline_ni_json}" \
  $NATIVE_IMAGE_EXTRA_ARGS -jar "$baseline_jar" -o "$baseline_bin"
t1="$(now_ns)"
baseline_ni_ns=$((t1 - t0))
baseline_bin_bytes="$(stat -c '%s' "$baseline_bin")"
baseline_out="$("$baseline_bin")"

elide_extra_args=()
if [[ "$(basename "$FIXTURE_DIR")" == "example-basic-app" ]]; then
  elide_extra_args+=(
    -Dmaven.compiler.proc=none
    -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
  )
fi

echo "==> [2/2] Building WITH elision (-Delide.mode=elision, trimJars=${TRIM_JARS})..."
t0="$(now_ns)"
run_logged env JAVA_HOME="$GRAALVM_HOME" "$MAVEN" --batch-mode --no-transfer-progress --offline \
  -f "$FIXTURE_DIR/pom.xml" -DskipTests=true \
  -Delide.mode=elision "-Delide.trimJars=${TRIM_JARS}" "-Delide.traceFiles=${trace_file}" \
  "${elide_extra_args[@]}" \
  clean package
t1="$(now_ns)"
elided_pkg_ns=$((t1 - t0))

elided_jar="$(find_shaded_jar)"
elided_jar_bytes="$(stat -c '%s' "$elided_jar")"

echo "==> [2/2] Compiling native binary WITH elision..."
elided_bin="$TMP_DIR/app-elided"
elided_ni_json="$TMP_DIR/elided-ni.json"
t0="$(now_ns)"
# shellcheck disable=SC2086
run_logged env JAVA_HOME="$GRAALVM_HOME" "$NATIVE_IMAGE_BIN" --no-fallback \
  --enable-sbom=cyclonedx,export "-H:BuildOutputJSONFile=${elided_ni_json}" \
  $NATIVE_IMAGE_EXTRA_ARGS -jar "$elided_jar" -o "$elided_bin"
t1="$(now_ns)"
elided_ni_ns=$((t1 - t0))
elided_bin_bytes="$(stat -c '%s' "$elided_bin")"
elided_out="$("$elided_bin")"

if [[ "$baseline_out" != "$elided_out" ]]; then
  echo "ERROR: Native binary output mismatch!" >&2
  echo "  Baseline: $baseline_out" >&2
  echo "  Elided:   $elided_out" >&2
  exit 1
fi

baseline_total_ns=$((baseline_pkg_ns + baseline_ni_ns))
elided_total_ns=$((elided_pkg_ns + elided_ni_ns))

echo
printf '%-28s %14s %14s %10s\n' "Metric" "Without Elision" "With Elision" "Delta"
printf '%-28s %14s %14s %10s\n' "----------------------------" "--------------" "------------" "----------"
printf '%-28s %13ss %13ss %10s\n' \
  "native-image compile" \
  "$(format_seconds 0 "$baseline_ni_ns")" \
  "$(format_seconds 0 "$elided_ni_ns")" \
  "$(pct_change "$((baseline_ni_ns / 1000000))" "$((elided_ni_ns / 1000000))")"
printf '%-28s %13ss %13ss %10s\n' \
  "Maven clean package" \
  "$(format_seconds 0 "$baseline_pkg_ns")" \
  "$(format_seconds 0 "$elided_pkg_ns")" \
  "$(pct_change "$((baseline_pkg_ns / 1000000))" "$((elided_pkg_ns / 1000000))")"
printf '%-28s %13ss %13ss %10s\n' \
  "Total (package + native)" \
  "$(format_seconds 0 "$baseline_total_ns")" \
  "$(format_seconds 0 "$elided_total_ns")" \
  "$(pct_change "$((baseline_total_ns / 1000000))" "$((elided_total_ns / 1000000))")"
printf '%-28s %12s B %12s B %10s\n' \
  "Shaded JAR size" \
  "$baseline_jar_bytes" \
  "$elided_jar_bytes" \
  "$(pct_change "$baseline_jar_bytes" "$elided_jar_bytes")"
printf '%-28s %12s B %12s B %10s\n' \
  "Native binary size" \
  "$baseline_bin_bytes" \
  "$elided_bin_bytes" \
  "$(pct_change "$baseline_bin_bytes" "$elided_bin_bytes")"
echo
if command -v node >/dev/null 2>&1; then
  node - "$baseline_ni_json" "$elided_ni_json" "${baseline_bin}.sbom.json" "${elided_bin}.sbom.json" <<'NODE'
const fs = require("fs");
const [bJsonPath, eJsonPath, bSbomPath, eSbomPath] = process.argv.slice(2);
const b = JSON.parse(fs.readFileSync(bJsonPath, "utf8"));
const e = JSON.parse(fs.readFileSync(eJsonPath, "utf8"));
const row = (label, bv, ev) => {
  const diff = ev - bv;
  const sign = diff > 0 ? "+" : "";
  console.log(label.padEnd(28) + String(bv).padStart(15) + String(ev).padStart(15) + (sign + diff).padStart(11));
};
console.log("GraalVM BuildOutputJSONFile breakdown:");
row("Reachable classes", b.analysis_results.classes.reachable, e.analysis_results.classes.reachable);
row("Total classes", b.analysis_results.classes.total, e.analysis_results.classes.total);
row("Reachable methods", b.analysis_results.methods.reachable, e.analysis_results.methods.reachable);
row("Reachable fields", b.analysis_results.fields.reachable, e.analysis_results.fields.reachable);
row("Compilation units", b.image_details.code_area.compilation_units, e.image_details.code_area.compilation_units);
row("Code area bytes", b.image_details.code_area.bytes, e.image_details.code_area.bytes);
row("Image heap bytes", b.image_details.image_heap.bytes, e.image_details.image_heap.bytes);
row("Image heap objects", b.image_details.image_heap.objects.count, e.image_details.image_heap.objects.count);
row("Image heap resources", b.image_details.image_heap.resources.count, e.image_details.image_heap.resources.count);

if (fs.existsSync(bSbomPath) && fs.existsSync(eSbomPath)) {
  const bSbom = JSON.parse(fs.readFileSync(bSbomPath, "utf8"));
  const eSbom = JSON.parse(fs.readFileSync(eSbomPath, "utf8"));
  const comps = (s) => (s.components || []).map((c) => `${c.group || ""}:${c.name}:${c.version || ""}`);
  console.log("\nGraalVM SBOM components (without elision):", comps(bSbom));
  console.log("GraalVM SBOM components (with elision):   ", comps(eSbom));
}
NODE
fi
echo
echo "Smoke check output: $elided_out"
