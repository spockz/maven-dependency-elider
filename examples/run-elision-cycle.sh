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
    echo "JAVA_HOME must point to a supported JDK; full verification currently targets GraalVM JDK 21" >&2
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
    elision_options=(
      -Delide.skip=false
      "-Delide.traceFiles=$trace"
      -Delider.verifyElision=true
    )
    baseline_package_bytes=0
    if [[ $fixture == example-basic-app ]]; then
      elision_options+=(
        -Delide.trimJars=true
        -Delide.sourceRootsComplete=true
        -Dmaven.compiler.proc=none
        -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
      )
    elif [[ $fixture == example-spring-boot-app ]]; then
      elision_options+=(
        -Delide.trimJars=true
        -Delide.sourceRootsComplete=true
        -Dmaven.compiler.proc=none
        -Delide.trimRoots=freemarker.template.Configuration,groovy.text.markup.MarkupTemplateEngine,jakarta.validation.Validation,org.webjars.WebJarAssetLocator,org.reactivestreams.Publisher,io.micrometer.context.ContextSnapshot,reactor.core.publisher.Flux,reactor.core.publisher.Mono,reactor.util.context.Context,jakarta.servlet.jsp.jstl.core.Config,javax.annotation.Nonnull,edu.umd.cs.findbugs.annotations.SuppressFBWarnings,com.thoughtworks.xstream.XStream,com.thoughtworks.xstream.io.xml.StaxDriver
        -Delide.trimSkipArtifacts=org.springframework.boot:spring-boot:3.3.5:jar:,org.springframework.boot:spring-boot-autoconfigure:3.3.5:jar:,org.springframework:spring-web:6.1.14:jar:,org.springframework:spring-context:6.1.14:jar:,org.springframework:spring-context-support:6.1.14:jar:,org.springframework:spring-beans:6.1.14:jar:,org.springframework:spring-aop:6.1.14:jar:,org.springframework:spring-expression:6.1.14:jar:,io.micrometer:micrometer-observation:1.13.6:jar:,io.micrometer:micrometer-commons:1.13.6:jar:,org.apache.groovy:groovy-templates:4.0.23:jar:
      )
    else
      elision_options+=(
        -Delide.sourceRootsComplete=true
        -Dmaven.compiler.proc=none
      )
    fi

    "$maven" "${maven_options[@]}" -f "$pom" clean verify \
      -Delide.skip=true -Delider.verifyElision=false
    test -f "$jar_file"
    if [[ $fixture == example-basic-app ]]; then
      baseline_package_bytes=$(wc -c <"$jar_file")
      original_compress_dir="$test_dir/basic-original"
      mkdir -p -- "$original_compress_dir"
      "$maven" "${maven_options[@]}" -f "$pom" dependency:copy \
        -Dartifact=org.apache.commons:commons-compress:1.28.0 \
        "-DoutputDirectory=$original_compress_dir"
    elif [[ $fixture == example-spring-boot-app ]]; then
      baseline_package_bytes=$(wc -c <"$jar_file")
    fi
    baseline_entries="$test_dir/$fixture-baseline.jar-entries"
    "$jar" tf "$jar_file" >"$baseline_entries"
    verify_baseline_archive "$fixture" "$baseline_entries"
    if [[ $fixture == example-spring-boot-app ]]; then
      mail_artifacts="$test_dir/$fixture-mail-artifacts"
      python3 "$repo_root/examples/support/verify_spring_mail_artifacts.py" \
        capture "$jar_file" "$mail_artifacts"
      python3 "$repo_root/examples/support/verify_spring_trimmed_artifacts.py" \
        capture "$jar_file" "$test_dir/$fixture-spring-webmvc.jar"
      python3 "$repo_root/examples/support/verify_spring_trimmed_artifacts.py" \
        capture-skip "$jar_file" "$test_dir/$fixture-passthrough-jars"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/run_spring_boot_endpoint.py" \
        "$java" "$jar_file" "$trace" "$baseline_output"
      verify_spring_unused_trace "$trace"
      production_output="$test_dir/$fixture-production-classes"
      usage_report="$test_dir/$fixture-class-usage.json"
      cp -a -- "$fixture_dir/target/classes" "$production_output"
      elision_options+=(
        "-Delide.productionOutput=$production_output"
        "-Delide.reportFile=$usage_report"
      )
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" "-Xlog:class+load=info:file=$trace" -jar "$jar_file" >"$baseline_output"
      if [[ $fixture == example-basic-app ]]; then
        verify_basic_unused_trace "$trace"
        verify_source_root_compiler_visibility "$repo_root" "$test_dir" "$trace"
      fi
    fi

    "$maven" "${maven_options[@]}" -f "$pom" clean verify "${elision_options[@]}"

    if [[ $fixture == example-basic-app ]]; then
      verify_basic_shade_input_paths "$fixture_dir"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/verify_class_usage_report.py" \
        "$usage_report" "$production_output"
    fi

    entries="$test_dir/$fixture.jar-entries"
    "$jar" tf "$jar_file" >"$entries"
    verify_archive "$fixture" "$entries"
    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/verify_spring_mail_artifacts.py" \
        compare "$jar_file" "$mail_artifacts"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/run_spring_boot_endpoint.py" \
        "$java" "$jar_file" "$test_dir/$fixture-final.log" "$final_output"
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" -jar "$jar_file" >"$final_output"
    fi
    verify_runtime "$fixture" "$final_output"
    if [[ $fixture == example-basic-app ]]; then
      verify_basic_trimmed_artifacts "$fixture_dir" "$jar_file" \
        "$test_dir/basic-original/commons-compress-1.28.0.jar" "$baseline_package_bytes"
    elif [[ $fixture == example-spring-boot-app ]]; then
      python3 "$repo_root/examples/support/verify_spring_trimmed_artifacts.py" \
        compare "$jar_file" "$test_dir/$fixture-spring-webmvc.jar"
      python3 "$repo_root/examples/support/verify_spring_trimmed_artifacts.py" \
        compare-skip "$jar_file" "$test_dir/$fixture-passthrough-jars"
      final_package_bytes=$(wc -c <"$jar_file")
      if (( final_package_bytes >= baseline_package_bytes )); then
        echo "Spring Boot package did not shrink: $baseline_package_bytes to $final_package_bytes bytes" >&2
        exit 1
      fi
      printf 'Spring Boot package shrank from %s to %s bytes (%s bytes removed)\n' \
        "$baseline_package_bytes" "$final_package_bytes" \
        "$((baseline_package_bytes - final_package_bytes))"
    fi
  done

  echo "Example elision lifecycle checks passed for ${#fixture_names[@]} fixtures."
}

verify_source_root_compiler_visibility() {
  local repo_root=$1
  local test_dir=$2
  local trace=$3
  local probe_root="$test_dir/compiler-visibility-probe"
  local probe_examples="$probe_root/examples"
  local probe_fixture="$probe_examples/example-basic-app"
  local probe_pom="$probe_fixture/pom.xml"
  local active_log="$test_dir/compiler-visibility-source-root.log"
  local skipped_log="$test_dir/compiler-visibility-skipped.log"

  mkdir -p "$probe_fixture"
  cp -- "$repo_root/pom.xml" "$probe_root/pom.xml"
  cp -- "$repo_root/examples/pom.xml" "$probe_examples/pom.xml"
  cp -- "$repo_root/examples/example-basic-app/pom.xml" "$probe_fixture/pom.xml"
  cp -a -- "$repo_root/examples/example-basic-app/src" "$probe_fixture/src"
  mkdir -p "$probe_fixture/src/main/java/io/github/spockz/example/basic"
  cat >"$probe_fixture/src/main/java/io/github/spockz/example/basic/ElidedCodecReference.java" <<'JAVA'
/* WHY: Provides a compile-time reference to the dependency removed by the recorded runtime trace. */
package io.github.spockz.example.basic;

import org.apache.commons.codec.binary.Hex;

/** Confirms compiler visibility follows the active Maven artifact set. */
final class ElidedCodecReference {
  private ElidedCodecReference() {}

  static String encode(final byte[] value) {
    return Hex.encodeHexString(value);
  }
}
JAVA

  "$maven" "${maven_options[@]}" -f "$probe_pom" clean compile \
    -Delide.skip=false -Delide.traceFiles="$trace" -Delider.verifyElision=false \
    -Delide.sourceRootsComplete=true -Dmaven.compiler.proc=none \
    >"$active_log" 2>&1
  if [[ ! -f $probe_fixture/target/classes/io/github/spockz/example/basic/ElidedCodecReference.class ]]; then
    echo "Compiler did not produce the source-root probe class when elision was enabled" >&2
    cat "$active_log" >&2
    exit 1
  fi

  "$maven" "${maven_options[@]}" -f "$probe_pom" clean compile \
    -Delide.skip=true -Delide.traceFiles="$trace" -Delider.verifyElision=false \
    >"$skipped_log" 2>&1
  if [[ ! -f $probe_fixture/target/classes/io/github/spockz/example/basic/ElidedCodecReference.class ]]; then
    echo "Compiler did not produce the probe class when elision was skipped" >&2
    cat "$skipped_log" >&2
    exit 1
  fi
  echo "Compiler visibility probe passed: the source-root reference retained Commons Codec before javac; skipped compile succeeds."
}

verify_basic_unused_trace() {
  local trace=$1
  if grep -Eq 'org\.apache\.commons\.codec\.' "$trace"; then
    echo "Commons Codec classes were loaded by the basic example" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not read basic application class-load trace $trace" >&2
      exit "$status"
    fi
  fi
}

verify_baseline_archive() {
  local fixture=$1
  local entries=$2
  case $fixture in
    example-basic-app)
      has_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      has_entry "$entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
      has_entry "$entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
      ;;
    example-spring-boot-app)
      has_pattern "$entries" 'BOOT-INF/lib/spring-webmvc-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/commons-codec-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/spring-context-support-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.mail-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.activation-api-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/angus-activation-[^/]+\.jar'
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
      lacks_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      has_entry "$entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
      lacks_entry "$entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
      ;;
    example-spring-boot-app)
      has_pattern "$entries" 'BOOT-INF/lib/spring-webmvc-[^/]+\.jar'
      lacks_pattern "$entries" 'BOOT-INF/lib/commons-codec-[^/]+\.jar'
      lacks_pattern "$entries" 'BOOT-INF/lib/snakeyaml-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/spring-context-support-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.mail-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.activation-api-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/angus-activation-[^/]+\.jar'
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

verify_basic_trimmed_artifacts() {
  local fixture_dir=$1
  local shaded_jar=$2
  local original_compress=$3
  local baseline_package_bytes=$4
  local trimmed_compress="$fixture_dir/target/elided-artifacts/org.apache.commons-commons-compress-1.28.0-trimmed.jar"
  local trimmed_entries="$test_dir/basic-compress-entries"
  local trimmed_package_bytes
  local original_compress_bytes
  local trimmed_compress_bytes

  test -f "$original_compress"
  test -f "$trimmed_compress"
  "$jar" tf "$trimmed_compress" >"$trimmed_entries"
  has_entry "$trimmed_entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
  lacks_entry "$trimmed_entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
  trimmed_package_bytes=$(wc -c <"$shaded_jar")
  original_compress_bytes=$(wc -c <"$original_compress")
  trimmed_compress_bytes=$(wc -c <"$trimmed_compress")
  if (( trimmed_package_bytes >= baseline_package_bytes )); then
    echo "Basic shaded JAR did not shrink: baseline=$baseline_package_bytes final=$trimmed_package_bytes" >&2
    exit 1
  fi
  if (( trimmed_compress_bytes >= original_compress_bytes )); then
    echo "Commons Compress JAR did not shrink: original=$original_compress_bytes trimmed=$trimmed_compress_bytes" >&2
    exit 1
  fi
  echo "Commons Compress JAR shrank from $original_compress_bytes to $trimmed_compress_bytes bytes; shaded JAR shrank from $baseline_package_bytes to $trimmed_package_bytes bytes."
}

verify_basic_shade_input_paths() {
  local fixture_dir=$1
  local observed="$fixture_dir/target/dependency-elider-shade-inputs.txt"
  local trimmed="$fixture_dir/target/elided-artifacts/org.apache.commons-commons-compress-1.28.0-trimmed.jar"
  test -f "$observed"
  grep -Fq -- "$trimmed" "$observed" || {
    echo "The same-session MavenProject classpath before Shade does not contain trimmed Compress: $observed" >&2
    exit 1
  }
  if grep -Fq -- '/commons-codec/commons-codec/' "$observed"; then
    echo "The same-session MavenProject classpath before Shade still contains elided Commons Codec: $observed" >&2
    exit 1
  fi
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
