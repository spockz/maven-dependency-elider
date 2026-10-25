#!/usr/bin/env bash
# WHY: Runs the trace, elide, package, runtime, and archive checks that make example expectations reproducible.
set -euo pipefail

main() {
  repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  maven=${MAVEN:-"$repo_root/.scratch/toolchains/maven-mvnd-1.0.6/bin/mvnd"}
  maven_args=${MAVEN_ARGS:---batch-mode --no-transfer-progress}
  app_timeout=${APP_TIMEOUT:-30s}
  if [[ $maven != /* ]]; then
    if [[ $maven == */* ]]; then
      maven="$repo_root/$maven"
    else
      maven=$(command -v "$maven")
    fi
  fi
  if [[ -n ${JAVA_HOME:-} ]]; then
    java="$JAVA_HOME/bin/java"
    jar="$JAVA_HOME/bin/jar"
  else
    echo "JAVA_HOME must point to GraalVM JDK 25" >&2
    exit 2
  fi
  if [[ ! -x $maven || ! -x $java || ! -x $jar ]] || ! command -v timeout >/dev/null; then
    echo "Maven, Java, jar, or timeout executable is missing" >&2
    exit 2
  fi

  read -r -a maven_options <<<"$maven_args"
  test_dir=$(mktemp -d "${TMPDIR:-/tmp}/maven-dependency-elider-examples.XXXXXX")
  cleanup() {
    local status=$?
    if [[ $status -eq 0 ]]; then
      rm -rf -- "$test_dir"
    else
      printf 'Example evidence retained at %s\n' "$test_dir" >&2
    fi
  }
  trap cleanup EXIT

  "$maven" "${maven_options[@]}" -f "$repo_root/pom.xml" \
    -pl dependency-elider-maven-plugin -am install

  fixture_names=(
    example-basic-app
    example-spring-boot-app
    example-cve-unused-app
    example-cve-safe-class-app
  )

  for fixture in "${fixture_names[@]}"; do
    fixture_dir="$repo_root/examples/$fixture"
    pom="$fixture_dir/pom.xml"
    jar_file="$fixture_dir/target/$fixture-0.1.0-SNAPSHOT.jar"
    trace="$test_dir/$fixture.log"
    baseline_output="$test_dir/$fixture-baseline.out"
    final_output="$test_dir/$fixture-final.out"

    "$maven" "${maven_options[@]}" -f "$pom" clean verify \
      -Delide.skip=true -Delider.verifyElision=false
    test -f "$jar_file"
    baseline_entries="$test_dir/$fixture-baseline.jar-entries"
    "$jar" tf "$jar_file" >"$baseline_entries"
    verify_baseline_archive "$fixture" "$baseline_entries"

    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/run_spring_boot_endpoint.py" \
        "$java" "$jar_file" "$trace" "$baseline_output"
      verify_spring_unused_trace "$trace"
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" "-Xlog:class+load=info:file=$trace" -jar "$jar_file" >"$baseline_output"
    fi

    "$maven" "${maven_options[@]}" -f "$pom" clean verify \
      -Delide.skip=false -Delide.traceFiles="$trace" -Delider.verifyElision=true

    entries="$test_dir/$fixture.jar-entries"
    "$jar" tf "$jar_file" >"$entries"
    verify_archive "$fixture" "$entries"

    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/run_spring_boot_endpoint.py" \
        "$java" "$jar_file" "$test_dir/$fixture-final.log" "$final_output"
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" -jar "$jar_file" >"$final_output"
    fi
    verify_runtime "$fixture" "$final_output"
  done

  echo "Example elision lifecycle checks passed for ${#fixture_names[@]} fixtures."
}

verify_baseline_archive() {
  local fixture=$1
  local entries=$2
  case $fixture in
    example-basic-app)
      has_entry "$entries" 'com/fasterxml/jackson/databind/ObjectMapper.class'
      has_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      ;;
    example-spring-boot-app)
      has_pattern "$entries" 'BOOT-INF/lib/spring-webmvc-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/commons-codec-[^/]+\.jar'
      ;;
    example-cve-unused-app)
      has_entry "$entries" 'com/fasterxml/jackson/databind/ObjectMapper.class'
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      has_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      has_prefix "$entries" 'org/codehaus/commons/compiler/'
      has_prefix "$entries" 'org/springframework/'
      ;;
    example-cve-safe-class-app)
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      has_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      has_prefix "$entries" 'org/codehaus/commons/compiler/'
      ;;
  esac
}

verify_archive() {
  local fixture=$1
  local entries=$2
  case $fixture in
    example-basic-app)
      has_entry "$entries" 'com/fasterxml/jackson/databind/ObjectMapper.class'
      lacks_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      ;;
    example-spring-boot-app)
      has_pattern "$entries" 'BOOT-INF/lib/spring-webmvc-[^/]+\.jar'
      lacks_pattern "$entries" 'BOOT-INF/lib/commons-codec-[^/]+\.jar'
      ;;
    example-cve-unused-app)
      has_entry "$entries" 'com/fasterxml/jackson/databind/ObjectMapper.class'
      lacks_prefix "$entries" 'ch/qos/logback/'
      lacks_prefix "$entries" 'org/codehaus/janino/'
      lacks_prefix "$entries" 'org/codehaus/commons/compiler/'
      lacks_prefix "$entries" 'org/springframework/'
      ;;
    example-cve-safe-class-app)
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      lacks_prefix "$entries" 'org/codehaus/janino/'
      lacks_prefix "$entries" 'org/codehaus/commons/compiler/'
      ;;
  esac
}

verify_runtime() {
  local fixture=$1
  local output=$2
  case $fixture in
    example-basic-app)
      test "$(<"$output")" = '{"message":"hello"}'
      ;;
    example-spring-boot-app)
      test -s "$output"
      ;;
    example-cve-unused-app)
      test "$(<"$output")" = '{"fixture":"unused-security"}'
      ;;
    example-cve-safe-class-app)
      grep -Fq 'safe class usage' "$output"
      ;;
  esac
}

verify_spring_unused_trace() {
  local trace=$1
  if grep -Eq 'org\.apache\.commons\.codec\.' "$trace"; then
    echo "Commons Codec classes were loaded by the Spring Boot example" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not read Spring Boot class-load trace $trace" >&2
      exit "$status"
    fi
  fi
}

has_entry() {
  grep -Fqx -- "$2" "$1" || { echo "Expected JAR entry $2 in $1" >&2; exit 1; }
}

lacks_entry() {
  if grep -Fqx -- "$2" "$1"; then
    echo "Unexpected JAR entry $2 in $1" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not inspect JAR entries in $1" >&2
      exit "$status"
    fi
  fi
}

has_prefix() {
  grep -Fq -- "$2" "$1" || { echo "Expected JAR entries under $2 in $1" >&2; exit 1; }
}

has_pattern() {
  grep -Eq -- "$2" "$1" || { echo "Expected JAR entry matching $2 in $1" >&2; exit 1; }
}

lacks_pattern() {
  if grep -Eq -- "$2" "$1"; then
    echo "Unexpected JAR entry matching $2 in $1" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not inspect JAR entries in $1" >&2
      exit "$status"
    fi
  fi
}

lacks_prefix() {
  if grep -Fq -- "$2" "$1"; then
    echo "Unexpected JAR entries under $2 in $1" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not inspect JAR entries in $1" >&2
      exit "$status"
    fi
  fi
}

main "$@"
