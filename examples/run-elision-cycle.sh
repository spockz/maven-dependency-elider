#!/usr/bin/env bash
# WHY: Runs reproducible example checks with project paths and temporary evidence anchored at the repository root.
set -euo pipefail

configured_passthrough_names=(
  groovy-templates-4.0.23.jar micrometer-commons-1.13.6.jar micrometer-jakarta9-1.13.6.jar
  micrometer-observation-1.13.6.jar spring-aop-6.1.14.jar
  spring-beans-6.1.14.jar spring-boot-3.3.5.jar
  spring-boot-autoconfigure-3.3.5.jar spring-context-6.1.14.jar
  spring-context-support-6.1.14.jar spring-expression-6.1.14.jar spring-web-6.1.14.jar
)
automatic_passthrough_names=(
  angus-activation-2.0.2.jar jackson-annotations-2.18.2.jar jackson-core-2.18.2.jar
  jakarta.activation-api-2.1.3.jar jakarta.annotation-api-2.1.1.jar jakarta.mail-2.0.3.jar
  jakarta.servlet.jsp.jstl-api-3.0.2.jar jakarta.validation-api-3.0.2.jar log4j-api-2.23.1.jar
  log4j-to-slf4j-2.23.1.jar logback-classic-1.5.11.jar logback-core-1.5.11.jar
  micrometer-core-1.13.6.jar
  reactor-core-3.6.11.jar snakeyaml-2.2.jar spring-core-6.1.14.jar tomcat-embed-core-10.1.31.jar
  tomcat-embed-el-10.1.31.jar tomcat-embed-websocket-10.1.31.jar
)

main() {
  repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  cd -- "$repo_root"
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
    java_home=$JAVA_HOME
    if [[ $java_home != /* ]]; then
      java_home="$repo_root/$java_home"
    fi
    java="$java_home/bin/java"
    javac="$java_home/bin/javac"
    jar="$java_home/bin/jar"
  else
    echo "JAVA_HOME must point to a supported JDK; full verification currently targets GraalVM JDK 21" >&2
    exit 2
  fi
  if [[ ! -x $maven || ! -x $java || ! -x $javac || ! -x $jar ]] || ! command -v timeout >/dev/null; then
    echo "Maven, javac, Java, jar, or timeout executable is missing" >&2
    exit 2
  fi

  read -r -a maven_options <<<"$maven_args"
  maven_options_without_threads=()
  skip_thread_count=false
  for option in "${maven_options[@]}"; do
    if [[ $skip_thread_count == true ]]; then
      skip_thread_count=false
    elif [[ $option == -T || $option == --threads ]]; then
      skip_thread_count=true
    elif [[ $option == -T* || $option == --threads=* ]]; then
      continue
    else
      maven_options_without_threads+=("$option")
    fi
  done

  run_timed() {
    local timing_file=$1
    local started
    local finished
    shift
    started=$(date +%s%N)
    "$@"
    finished=$(date +%s%N)
    printf '%s\n' "$((finished - started))" >"$timing_file"
  }

  mkdir -p -- "$repo_root/.scratch"
  test_dir=$(mktemp -d "$repo_root/.scratch/maven-dependency-elider-examples.XXXXXX")
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
    -pl dependency-elider-maven-plugin -am install -DskipTests

  run_fixture_maven() {
    local fixture_dir=$1
    shift
    (cd -- "$fixture_dir" && "$maven" "${maven_options[@]}" "$@")
  }

  run_reactor_maven() {
    local fixture_dir=$1
    shift
    (cd -- "$fixture_dir" && env -u MAVEN_ARGS "$maven" "${maven_options_without_threads[@]}" "$@")
  }

  dependency_classpath="$test_dir/example-support.classpath"
  "$maven" "${maven_options[@]}" -f "$repo_root/dependency-elider-maven-plugin/pom.xml" \
    dependency:build-classpath -DincludeScope=test "-Dmdep.outputFile=$dependency_classpath"
  support_classes="$test_dir/example-support-classes"
  support_classpath="$support_classes:$(<"$dependency_classpath")"
  mkdir -p -- "$support_classes"
  "$javac" -classpath "$(<"$dependency_classpath")" -d "$support_classes" \
    "$repo_root/examples/support/ExampleSupport.java" \
    "$repo_root/examples/support/ExampleSupportContractTest.java"
  "$java" "-Djava.io.tmpdir=$test_dir" --class-path "$support_classpath" ExampleSupportContractTest

  if [[ ${REACTOR_ONLY:-false} == true ]]; then
    fixture_names=()
  else
    fixture_names=(
      example-basic-app
      example-spring-boot-app
      example-cve-unused-app
      example-cve-safe-class-app
    )
  fi

  for fixture in "${fixture_names[@]}"; do
    fixture_dir="$repo_root/examples/$fixture"
    pom="$fixture_dir/pom.xml"
    jar_file="$fixture_dir/target/$fixture-0.1.0-SNAPSHOT.jar"
    trace="$test_dir/$fixture.log"
    baseline_output="$test_dir/$fixture-baseline.out"
    final_output="$test_dir/$fixture-final.out"
    baseline_seconds="$test_dir/$fixture-baseline.seconds"
    elision_seconds="$test_dir/$fixture-elision.seconds"
    elision_options=(
      -Delide.mode=elision
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
        -Delide.trimSkipArtifacts=org.springframework.boot:spring-boot:3.3.5:jar:,org.springframework.boot:spring-boot-autoconfigure:3.3.5:jar:,org.springframework.boot:spring-boot-actuator:3.3.5:jar:,org.springframework.boot:spring-boot-actuator-autoconfigure:3.3.5:jar:,org.springframework:spring-web:6.1.14:jar:,org.springframework:spring-context:6.1.14:jar:,org.springframework:spring-context-support:6.1.14:jar:,org.springframework:spring-beans:6.1.14:jar:,org.springframework:spring-aop:6.1.14:jar:,org.springframework:spring-expression:6.1.14:jar:,io.micrometer:micrometer-observation:1.13.6:jar:,io.micrometer:micrometer-commons:1.13.6:jar:,io.micrometer:micrometer-jakarta9:1.13.6:jar:,org.apache.groovy:groovy-templates:4.0.23:jar:
      )
    elif [[ $fixture == example-cve-unused-app || $fixture == example-cve-safe-class-app ]]; then
      elision_options+=(
        -Delide.trimJars=true
        -Delide.sourceRootsComplete=true
        -Dmaven.compiler.proc=none
        -Delide.trimSkipArtifacts=org.springframework:spring-context:6.2.7:jar:,org.springframework:spring-beans:6.2.7:jar:,org.springframework:spring-aop:6.2.7:jar:,org.springframework:spring-expression:6.2.7:jar:,org.springframework:spring-jcl:6.2.7:jar:,io.micrometer:micrometer-observation:1.15.0:jar:,io.micrometer:micrometer-commons:1.15.0:jar:
      )
    else
      elision_options+=(
        -Delide.sourceRootsComplete=true
        -Delide.trimJars=true
        -Dmaven.compiler.proc=none
      )
    fi

    run_timed "$baseline_seconds" run_fixture_maven "$fixture_dir" -f "$pom" clean verify \
      -Delide.mode=baseline -Delider.verifyElision=false
    test -f "$jar_file"
    if [[ $fixture == example-basic-app ]]; then
      baseline_package_bytes=$(wc -c <"$jar_file")
      original_compress_dir="$test_dir/basic-original"
      mkdir -p -- "$original_compress_dir"
      run_fixture_maven "$fixture_dir" -f "$pom" dependency:copy \
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
      capture_spring_mail_artifacts "$jar_file" "$mail_artifacts"
      capture_spring_webmvc "$jar_file" "$test_dir/$fixture-spring-webmvc.jar"
      capture_spring_passthrough "$jar_file" "$test_dir/$fixture-passthrough-jars"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      run_spring_boot_endpoint "$jar_file" "$trace" "$baseline_output"
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
        tree_output="$test_dir/$fixture-elided-tree.out"
        run_fixture_maven "$fixture_dir" -f "$pom" "${elision_options[@]}" dependency:tree \
          >"$tree_output"
        verify_basic_elided_tree "$tree_output"
        verify_source_root_compiler_visibility "$repo_root" "$test_dir" "$trace"
      fi
    fi

    run_timed "$elision_seconds" run_fixture_maven "$fixture_dir" -f "$pom" clean verify "${elision_options[@]}"

    if [[ $fixture == example-basic-app || $fixture == example-spring-boot-app ||
      $fixture == example-cve-unused-app || $fixture == example-cve-safe-class-app ]]; then
      test -f "$fixture_dir/target/classes/META-INF/sbom/application.cdx.json"
      test -f "$fixture_dir/target/classes/META-INF/native-image/sbom.json"
    fi

    if [[ $fixture == example-cve-unused-app || $fixture == example-cve-safe-class-app ]]; then
      verify_cve_sboms "$fixture" "$fixture_dir/target/baseline-sbom.cdx.json" \
        "$fixture_dir/target/dependency-elider-sbom.cdx.json" \
        "$fixture_dir/target/dependency-elider.openvex.json"
    fi

    if [[ $fixture == example-basic-app || $fixture == example-spring-boot-app ]]; then
      baseline_millis=$(( $(<"$baseline_seconds") / 1000000 ))
      elision_millis=$(( $(<"$elision_seconds") / 1000000 ))
      awk -v fixture="$fixture" -v baseline="$baseline_millis" -v elision="$elision_millis" \
        'BEGIN { printf "Maven clean verify timing for %s: baseline=%.3fs, elision=%.3fs, difference=%+.3fs\n", fixture, baseline / 1000, elision / 1000, (elision - baseline) / 1000 }'
    fi

    if [[ $fixture == example-basic-app ]]; then
      verify_basic_shade_input_paths "$fixture_dir"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      "$java" --class-path "$support_classpath" ExampleSupport \
        verify-class-report "$usage_report" "$production_output"
    fi

    report_output="$test_dir/$fixture-elision-report.out"
    run_fixture_maven "$fixture_dir" -f "$pom" \
      io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report >"$report_output" 2>&1
    printf '\n%s report:\n' "$fixture"
    grep -E '^\[INFO\] (Project:|Snapshot:|Whole artifacts dropped:|Program classes removed with dropped JARs:|Program classes pruned from retained JARs:|Avoided CVEs \(dropped artifacts\):|Mitigated CVEs \(vulnerable code pruned by trimming\):|CVEs inactive due to unmet prerequisite dependencies:|Potentially conservative CVE exclusions:|  - |    Reason:)' \
      "$report_output"
    verify_cve_report "$fixture" "$fixture_dir" "$report_output"

    entries="$test_dir/$fixture.jar-entries"
    "$jar" tf "$jar_file" >"$entries"
    verify_archive "$fixture" "$entries" "$fixture_dir"
    if [[ $fixture == example-spring-boot-app ]]; then
      compare_spring_mail_artifacts "$jar_file" "$mail_artifacts"
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      run_spring_boot_endpoint "$jar_file" "$test_dir/$fixture-final.log" "$final_output"
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" -jar "$jar_file" >"$final_output"
    fi
    verify_runtime "$fixture" "$final_output"
    if [[ $fixture == example-basic-app ]]; then
      verify_basic_trimmed_artifacts "$fixture_dir" "$jar_file" \
        "$test_dir/basic-original/commons-compress-1.28.0.jar" "$baseline_package_bytes"
    elif [[ $fixture == example-spring-boot-app ]]; then
      compare_spring_webmvc "$jar_file" "$test_dir/$fixture-spring-webmvc.jar"
      compare_spring_passthrough "$jar_file" "$test_dir/$fixture-passthrough-jars"
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

  run_reactor_fixture "$repo_root/examples/example-multi-module-reactor" "$test_dir"
  if [[ ${REACTOR_ONLY:-false} == true ]]; then
    echo "Multi-module reactor lifecycle checks passed."
  else
    echo "Example elision lifecycle checks passed for ${#fixture_names[@]} standalone fixtures and the multi-module reactor."
  fi
}

run_reactor_fixture() {
  local fixture_dir=$1
  local evidence_dir=$2
  local pom="$fixture_dir/pom.xml"
  local app_jar="$fixture_dir/reactor-app/target/reactor-app-0.1.0-SNAPSHOT.jar"
  local trace="$evidence_dir/example-multi-module-reactor.log"
  local baseline_output="$evidence_dir/example-multi-module-reactor-baseline.out"
  local final_output="$evidence_dir/example-multi-module-reactor-final.out"
  local baseline_entries="$evidence_dir/example-multi-module-reactor-baseline.entries"
  local final_entries="$evidence_dir/example-multi-module-reactor-final.entries"
  local sequential_build_log="$evidence_dir/reactor-sequential-build.log"
  local threaded_build_log="$evidence_dir/reactor-threaded-build.log"
  local user_repository_before="$evidence_dir/reactor-user-repository-before.tsv"
  local user_repository_after="$evidence_dir/reactor-user-repository-after.tsv"
  local local_repository
  local original_compress
  local original_compress_sha="$evidence_dir/reactor-original-compress.sha256"
  local sequential_reports="$evidence_dir/reactor-sequential-reports"
  local threaded_reports="$evidence_dir/reactor-threaded-reports"
  local report_output="$evidence_dir/reactor-report.out"
  local -a elision_options=(
    -Delide.mode=elision
    "-Delide.traceFiles=$trace"
    -Delide.trimJars=true
    -Delide.sourceRootsComplete=true
    -Dmaven.compiler.proc=none
    -Delider.verifyElision=true
  )

  local_repository=$(run_reactor_maven "$fixture_dir" -f "$pom" -q -DforceStdout \
    -Dexpression=settings.localRepository help:evaluate)
  if [[ -z $local_repository || ! -d $local_repository ]]; then
    echo "Maven reported an invalid local repository path: $local_repository" >&2
    exit 1
  fi
  local_repository=$(cd -- "$local_repository" && pwd -P)
  original_compress="$local_repository/org/apache/commons/commons-compress/1.28.0/commons-compress-1.28.0.jar"
  verify_reactor_user_repository "$local_repository" "$user_repository_before"

  run_reactor_maven "$fixture_dir" -f "$pom" clean verify \
    -Delide.mode=baseline -Delider.verifyElision=false
  test -f "$app_jar"
  test -f "$original_compress"
  sha256sum "$original_compress" >"$original_compress_sha"
  "$jar" tf "$app_jar" >"$baseline_entries"
  has_entry "$baseline_entries" 'org/apache/commons/codec/binary/Base64.class'
  has_entry "$baseline_entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
  has_entry "$baseline_entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
  timeout --signal=TERM --kill-after=5s "$app_timeout" \
    "$java" "-Xlog:class+load=info:file=$trace" -jar "$app_jar" >"$baseline_output"
  test "$(<"$baseline_output")" = 'processed: input.tar'
  verify_reactor_unused_trace "$trace"

  run_reactor_elision_build "$fixture_dir" "$pom" "${elision_options[@]}" \
    >"$sequential_build_log" 2>&1
  if grep -Fq 'Using the MultiThreadedBuilder' "$sequential_build_log"; then
    echo "Sequential reactor clean verify unexpectedly selected Maven's MultiThreadedBuilder" >&2
    exit 1
  fi
  printf 'Sequential reactor builder verified: default single-threaded Maven builder.\n'
  run_reactor_reports "$fixture_dir" "$pom" "$sequential_reports" "$report_output"
  for module in reactor-common reactor-service reactor-app; do
    cp -- "$fixture_dir/$module/target/dependency-elider-report.json" \
      "$sequential_reports/$module.json"
  done
  "$jar" tf "$app_jar" >"$final_entries"
  has_entry "$final_entries" 'io/github/spockz/example/reactor/app/MainApp.class'
  has_entry "$final_entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
  lacks_entry "$final_entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
  lacks_entry "$final_entries" 'org/apache/commons/codec/binary/Base64.class'
  timeout --signal=TERM --kill-after=5s "$app_timeout" "$java" -jar "$app_jar" >"$final_output"
  test "$(<"$final_output")" = 'processed: input.tar'
  verify_reactor_trimmed_compress "$fixture_dir"
  verify_reactor_shade_input_paths "$fixture_dir"
  verify_reactor_output_paths "$fixture_dir"
  sha256sum --check "$original_compress_sha"

  run_reactor_elision_build "$fixture_dir" "$pom" -T 4 "${elision_options[@]}" \
    >"$threaded_build_log" 2>&1
  grep -Fq 'Using the MultiThreadedBuilder implementation with a thread count of 4' \
    "$threaded_build_log" || {
    echo "Threaded reactor clean verify did not select Maven's -T 4 builder" >&2
    exit 1
  }
  grep -F 'Using the MultiThreadedBuilder implementation with a thread count of 4' \
    "$threaded_build_log"
  run_reactor_reports "$fixture_dir" "$pom" "$threaded_reports" "$report_output"
  for module in reactor-common reactor-service reactor-app; do
    cp -- "$fixture_dir/$module/target/dependency-elider-report.json" \
      "$threaded_reports/$module.json"
  done
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-reactor-reports "$sequential_reports" "$threaded_reports" "$fixture_dir"
  "$jar" tf "$app_jar" >"$final_entries"
  has_entry "$final_entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
  lacks_entry "$final_entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
  lacks_entry "$final_entries" 'org/apache/commons/codec/binary/Base64.class'
  timeout --signal=TERM --kill-after=5s "$app_timeout" "$java" -jar "$app_jar" >"$final_output"
  test "$(<"$final_output")" = 'processed: input.tar'
  verify_reactor_trimmed_compress "$fixture_dir"
  verify_reactor_shade_input_paths "$fixture_dir"
  verify_reactor_output_paths "$fixture_dir"
  sha256sum --check "$original_compress_sha"
  verify_reactor_user_repository "$local_repository" "$user_repository_after"
  if ! cmp -s -- "$user_repository_before" "$user_repository_after"; then
    diff -u -- "$user_repository_before" "$user_repository_after" >&2 || true
    echo "Reactor builds changed transformed-artifact outputs under Maven's local repository" >&2
    exit 1
  fi
  printf 'Multi-module reactor reports are independent schema-1 snapshots with matching sequential and -T 4 metrics.\n'
}

run_reactor_elision_build() {
  local fixture_dir=$1
  local pom=$2
  shift 2
  run_reactor_maven "$fixture_dir" -f "$pom" clean verify "$@"
}

run_reactor_reports() {
  local fixture_dir=$1
  local pom=$2
  local report_directory=$3
  local output=$4
  mkdir -p -- "$report_directory"
  run_reactor_maven "$fixture_dir" -f "$pom" -pl \
    reactor-common,reactor-service,reactor-app \
    io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report \
    >"$output" 2>&1
}

verify_reactor_unused_trace() {
  local trace=$1
  if grep -Eq 'org\.apache\.commons\.codec\.' "$trace"; then
    echo "Commons Codec classes were loaded by the multi-module reactor baseline" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not read multi-module reactor class-load trace $trace" >&2
      exit "$status"
    fi
  fi
}

verify_reactor_trimmed_compress() {
  local fixture_dir=$1
  local generations="$fixture_dir/reactor-common/target/elided-artifacts/.generations"
  local -a matches=()
  local entries="${fixture_dir}/reactor-common/target/commons-compress-trimmed.entries"
  mapfile -t matches < <(
    find "$generations" -mindepth 2 -maxdepth 2 -type f \
      -name 'org.apache.commons-commons-compress-1.28.0-trimmed.jar' -print
  )
  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "Expected one Commons Compress generation under $generations" >&2
    return 1
  fi
  "$jar" tf "${matches[0]}" >"$entries"
  has_entry "$entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
  lacks_entry "$entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
}

verify_reactor_shade_input_paths() {
  local fixture_dir=$1
  local app_target="$fixture_dir/reactor-app/target"
  local generations="$app_target/elided-artifacts/.generations"
  local observed="$app_target/dependency-elider-shade-inputs.txt"
  local -a matches=()
  mapfile -t matches < <(
    find "$generations" -mindepth 2 -maxdepth 2 -type f \
      -name 'org.apache.commons-commons-compress-1.28.0-trimmed.jar' -print
  )
  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "Expected one app-local Commons Compress generation under $generations" >&2
    return 1
  fi
  test -f "$observed"
  grep -Fq -- "${matches[0]}" "$observed" || {
    echo "Shade classpath does not contain the app-local trimmed Commons Compress: $observed" >&2
    exit 1
  }
  if grep -Fq '/commons-codec/commons-codec/' "$observed"; then
    echo "Shade classpath still contains Commons Codec: $observed" >&2
    exit 1
  fi
}

verify_reactor_output_paths() {
  local fixture_dir=$1
  local path
  while IFS= read -r -d '' path; do
    if [[ $path != "$fixture_dir"/reactor-*/target/elided-artifacts/* ]]; then
      echo "Transformed reactor artifact escaped its module target directory: $path" >&2
      return 1
    fi
  done < <(find "$fixture_dir" -type f -name '*-trimmed.jar' -print0)
}

verify_reactor_user_repository() {
  local repository=$1
  local inventory=$2
  local paths="$inventory.paths"
  local path
  local digest
  : >"$paths"
  while IFS= read -r -d '' path; do
    find "$path" -mindepth 0 -print0 >>"$paths"
  done < <(find "$repository" -type d -name elided-artifacts -prune -print0)
  find "$repository" -type f \
    \( -name '*-trimmed.jar' -o -name '.trim-analysis-cache.json' \) \
    -print0 >>"$paths"
  sort --zero-terminated --unique "$paths" --output="$paths"
  : >"$inventory"
  while IFS= read -r -d '' path; do
    local relative_path=${path#"$repository"/}
    if [[ -d $path ]]; then
      printf 'directory\t%s\n' "$relative_path" >>"$inventory"
    elif [[ -f $path ]]; then
      digest=$(sha256sum -- "$path")
      printf 'file\t%s\t%s\n' "${digest%% *}" "$relative_path" >>"$inventory"
    fi
  done <"$paths"
  rm -- "$paths"
}

verify_cve_sboms() {
  local fixture=$1
  local baseline=$2
  local post_elision=$3
  local vex=$4
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-cve-sboms "$fixture" "$baseline" "$post_elision" "$vex" \
    "$repo_root/elider-core/src/test/resources/schema/bom-1.6.schema.json" \
    "$repo_root/elider-core/src/test/resources/schema/openvex-0.2.0.schema.json"
}

run_spring_boot_endpoint() {
  local archive=$1
  local trace=$2
  local output=$3
  "$java" --class-path "$support_classpath" ExampleSupport \
    run-spring-endpoint "$java" "$archive" "$trace" "$output"
}

capture_spring_mail_artifacts() {
  local archive=$1
  local output_dir=$2
  local entries="$test_dir/spring-mail-entries"
  local manifest="$output_dir/sha256.txt"
  local -a patterns=(
    'BOOT-INF/lib/spring-context-support-[^/]+\.jar'
    'BOOT-INF/lib/jakarta\.mail-[^/]+\.jar'
    'BOOT-INF/lib/jakarta\.activation-api-[^/]+\.jar'
    'BOOT-INF/lib/angus-activation-[^/]+\.jar'
  )
  local pattern
  local entry
  local destination
  local digest
  mkdir -p -- "$output_dir"
  : >"$manifest"
  "$jar" tf "$archive" >"$entries"
  for pattern in "${patterns[@]}"; do
    mapfile -t matches < <(grep -E "^$pattern$" "$entries" || true)
    if [[ ${#matches[@]} -ne 1 ]]; then
      echo "Expected exactly one nested mail JAR matching $pattern in $archive; found ${#matches[@]}" >&2
      exit 1
    fi
    entry=${matches[0]}
    destination="$output_dir/${entry##*/}"
    extract_nested_jar "$archive" "$entry" "$destination"
    digest=$(sha256sum "$destination" | cut -d ' ' -f 1)
    printf '%s %s\n' "$entry" "$digest" >>"$manifest"
  done
  sort -o "$manifest" "$manifest"
}

compare_spring_mail_artifacts() {
  local archive=$1
  local baseline_dir=$2
  local current_dir="$test_dir/spring-mail-current"
  capture_spring_mail_artifacts "$archive" "$current_dir"
  cmp -- "$baseline_dir/sha256.txt" "$current_dir/sha256.txt" || {
    echo "Final Spring mail runtime JAR names or SHA-256 digests differ from baseline" >&2
    exit 1
  }
  while read -r entry _; do
    cmp -- "$baseline_dir/${entry##*/}" "$current_dir/${entry##*/}" || {
      echo "Nested mail JAR bytes changed for $entry" >&2
      exit 1
    }
  done <"$baseline_dir/sha256.txt"
}

capture_spring_webmvc() {
  local archive=$1
  local output=$2
  local entries="$test_dir/spring-webmvc-entries"
  local -a matches
  "$jar" tf "$archive" >"$entries"
  mapfile -t matches < <(grep -E '^BOOT-INF/lib/spring-webmvc-[^/]+\.jar$' "$entries" || true)
  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "Expected exactly one nested Spring MVC JAR in $archive; found ${#matches[@]}" >&2
    exit 1
  fi
  extract_nested_jar "$archive" "${matches[0]}" "$output"
}

compare_spring_webmvc() {
  local archive=$1
  local baseline=$2
  local current="$test_dir/spring-webmvc-current.jar"
  local baseline_classes="$test_dir/spring-webmvc-baseline-classes"
  local current_classes="$test_dir/spring-webmvc-current-classes"
  local extra_classes="$test_dir/spring-webmvc-extra-classes"
  capture_spring_webmvc "$archive" "$current"
  "$jar" tf "$baseline" | grep '\.class$' | sort >"$baseline_classes"
  "$jar" tf "$current" | grep '\.class$' | sort >"$current_classes"
  comm -23 "$current_classes" "$baseline_classes" >"$extra_classes"
  if [[ -s $extra_classes ]]; then
    echo "Trimmed Spring MVC JAR contains class entries absent from the original" >&2
    cat "$extra_classes" >&2
    exit 1
  fi
  local missing_classes="$test_dir/spring-webmvc-missing-classes"
  comm -13 "$current_classes" "$baseline_classes" >"$missing_classes"
  if [[ ! -s $missing_classes ]]; then
    echo "Nested Spring MVC JAR did not lose any class entries" >&2
    exit 1
  fi
  has_entry "$current_classes" 'org/springframework/web/servlet/DispatcherServlet.class'
  local baseline_bytes
  local current_bytes
  baseline_bytes=$(wc -c <"$baseline")
  current_bytes=$(wc -c <"$current")
  if (( current_bytes >= baseline_bytes )); then
    echo "Nested Spring MVC JAR did not shrink: $baseline_bytes to $current_bytes bytes" >&2
    exit 1
  fi
  printf 'Nested Spring MVC JAR shrank from %s to %s bytes and from %s to %s classes\n' \
    "$baseline_bytes" "$current_bytes" \
    "$(wc -l <"$baseline_classes")" "$(wc -l <"$current_classes")"
}

capture_spring_passthrough() {
  collect_spring_passthrough "$1" "$2" false
}

compare_spring_passthrough() {
  local archive=$1
  local baseline_dir=$2
  local current_dir="$test_dir/passthrough-current"
  local baseline_names="$test_dir/passthrough-baseline-names"
  local current_names="$test_dir/passthrough-current-names"
  collect_spring_passthrough "$archive" "$current_dir" true
  find "$baseline_dir" -type f -name '*.jar' -printf '%f\n' | sort >"$baseline_names"
  find "$current_dir" -type f -name '*.jar' -printf '%f\n' | sort >"$current_names"
  local configured
  for configured in "${configured_passthrough_names[@]}"; do
    grep -Fqx -- "$configured" "$current_names" || {
      echo "Configured pass-through JAR was not packaged: $configured" >&2
      exit 1
    }
  done
  diff -u "$baseline_names" "$current_names" || {
    echo "Set of pass-through nested JARs changed from baseline" >&2
    exit 1
  }
  local name
  while IFS= read -r name; do
    cmp -- "$baseline_dir/$name" "$current_dir/$name" || {
      echo "Pass-through JAR was modified: $name" >&2
      exit 1
    }
  done <"$current_names"
  printf '%s configured and %s automatic pass-through JAR(s) remained byte-identical\n' \
    "$(grep -Fxf <(printf '%s\n' "${configured_passthrough_names[@]}") "$current_names" | wc -l)" \
    "$(grep -Fxf <(printf '%s\n' "${automatic_passthrough_names[@]}") "$current_names" | wc -l)"
}

collect_spring_passthrough() {
  local archive=$1
  local output_dir=$2
  local reject_unknown=$3
  local entries="$test_dir/passthrough-entries"
  local staging="$test_dir/passthrough-stage"
  local entry
  local name
  local nested_listing
  local unsupported
  local selected
  mkdir -p -- "$output_dir" "$staging"
  "$jar" tf "$archive" >"$entries"
  while IFS= read -r entry; do
    [[ $entry == BOOT-INF/lib/*.jar ]] || continue
    name=${entry##*/}
    local nested="$staging/$name"
    extract_nested_jar "$archive" "$entry" "$nested"
    nested_listing="$staging/$name.entries"
    "$jar" tf "$nested" >"$nested_listing"
    unsupported=false
    if grep -Fqx 'module-info.class' "$nested_listing" || \
      awk '/^META-INF\/versions\/[0-9]+\/.*\.class$/ && $0 !~ /\/module-info\.class$/ { found=1 } END { exit !found }' "$nested_listing"; then
      unsupported=true
    fi
    selected=false
    if contains_string "$name" "${configured_passthrough_names[@]}"; then
      selected=true
    elif [[ $unsupported == true ]]; then
      if contains_string "$name" "${automatic_passthrough_names[@]}"; then
        selected=true
      elif [[ $reject_unknown == true ]]; then
        echo "Unknown automatic pass-through archive appeared: $name" >&2
        exit 1
      fi
    fi
    if [[ $selected == true ]]; then
      cp -- "$nested" "$output_dir/$name"
    fi
  done < <(grep -E '^BOOT-INF/lib/[^/]+\.jar$' "$entries")
}

contains_string() {
  local needle=$1
  shift
  local candidate
  for candidate in "$@"; do
    [[ $candidate == "$needle" ]] && return 0
  done
  return 1
}

extract_nested_jar() {
  local archive=$1
  local entry=$2
  local output=$3
  local extraction="$test_dir/extract-${BASHPID}"
  rm -rf -- "$extraction"
  mkdir -p -- "$extraction"
  (cd -- "$extraction" && "$jar" --extract --file "$archive" "$entry")
  mkdir -p -- "$(dirname -- "$output")"
  cp -- "$extraction/$entry" "$output"
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
  mkdir -p "$probe_fixture/.mvn"
  cp -- "$repo_root/examples/example-basic-app/.mvn/extensions.xml" "$probe_fixture/.mvn/extensions.xml"
  mkdir -p "$probe_fixture/src/main/java/io/github/spockz/example/basic"
  cat >"$probe_fixture/src/main/java/io/github/spockz/example/basic/ElidedHttpClientReference.java" <<'JAVA'
/* WHY: Provides a compile-time reference to the dependency removed by the recorded runtime trace. */
package io.github.spockz.example.basic;

import org.apache.http.client.HttpClient;

/** Confirms compiler visibility follows the active Maven artifact set. */
final class ElidedHttpClientReference {
  private ElidedHttpClientReference() {}

  static Class<?> clientType() {
    return HttpClient.class;
  }
}
JAVA

  (cd -- "$probe_fixture" && "$maven" "${maven_options[@]}" -f "$probe_pom" clean compile \
    -Delide.mode=elision -Delide.traceFiles="$trace" -Delider.verifyElision=false \
    -Delide.sourceRootsComplete=true -Dmaven.compiler.proc=none) \
    >"$active_log" 2>&1
  if [[ ! -f $probe_fixture/target/classes/io/github/spockz/example/basic/ElidedHttpClientReference.class ]]; then
    echo "Compiler did not produce the source-root probe class when elision was enabled" >&2
    cat "$active_log" >&2
    exit 1
  fi

  (cd -- "$probe_fixture" && "$maven" "${maven_options[@]}" -f "$probe_pom" clean compile \
    -Delide.mode=baseline -Delide.traceFiles="$trace" -Delider.verifyElision=false) \
    >"$skipped_log" 2>&1
  if [[ ! -f $probe_fixture/target/classes/io/github/spockz/example/basic/ElidedHttpClientReference.class ]]; then
    echo "Compiler did not produce the probe class when elision was skipped" >&2
    cat "$skipped_log" >&2
    exit 1
  fi
  echo "Compiler visibility probe passed: the source-root reference retained HttpClient before javac; skipped compile succeeds."
}

verify_basic_unused_trace() {
  local trace=$1
  if grep -Eq 'org\.apache\.commons\.codec\.|org\.apache\.http\.' "$trace"; then
    echo "Unused classes (Commons Codec or HttpClient) were loaded by the basic example" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not read basic application class-load trace $trace" >&2
      exit "$status"
    fi
  fi
}

verify_basic_elided_tree() {
  local output=$1
  local tree_output="$test_dir/basic-elided-tree-section.out"
  awk '/--- dependency:.*:tree / { in_tree=1 } in_tree { print }' "$output" >"$tree_output"
  if ! grep -Fq 'org.apache.commons:commons-compress:jar:1.28.0' "$tree_output"; then
    echo "Bare Basic dependency:tree did not retain Commons Compress: $output" >&2
    cat "$tree_output" >&2
    exit 1
  fi
  if grep -Fq 'commons-codec:commons-codec' "$tree_output" || grep -Fq 'org.apache.httpcomponents:httpclient' "$tree_output"; then
    echo "Bare Basic dependency:tree still contains dropped dependencies: $output" >&2
    cat "$tree_output" >&2
    exit 1
  else
    local status=$?
    if [[ $status -ne 1 ]]; then
      echo "Could not read Basic dependency:tree output $output" >&2
      exit "$status"
    fi
  fi
  printf 'Bare Basic dependency:tree omitted Commons Codec and HttpClient, and retained Commons Compress\n'
}

verify_baseline_archive() {
  local fixture=$1
  local entries=$2
  case $fixture in
    example-basic-app)
      has_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      has_entry "$entries" 'org/apache/http/client/HttpClient.class'
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
      has_entry "$entries" 'org/apache/commons/text/similarity/LevenshteinDistance.class'
      has_entry "$entries" 'org/apache/commons/text/lookup/StringLookup.class'
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      has_entry "$entries" 'org/codehaus/janino/ClassBodyEvaluator.class'
      has_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      has_prefix "$entries" 'org/codehaus/commons/compiler/'
      has_prefix "$entries" 'org/springframework/'
      ;;
    example-cve-safe-class-app)
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      lacks_entry "$entries" 'org/codehaus/janino/ClassBodyEvaluator.class'
      lacks_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      ;;
  esac
}

verify_archive() {
  local fixture=$1
  local entries=$2
  local fixture_dir=$3
  case $fixture in
    example-basic-app) verify_effective_graph_report "$fixture_dir" 2 ;;
    example-spring-boot-app) verify_effective_graph_report "$fixture_dir" 0 ;;
    example-cve-unused-app|example-cve-safe-class-app)
      verify_effective_graph_report "$fixture_dir" 0
      verify_no_cve_whole_artifact_drops "$fixture_dir"
      ;;
    *) verify_effective_graph_report "$fixture_dir" ;;
  esac
  case $fixture in
    example-basic-app)
      lacks_entry "$entries" 'org/apache/commons/codec/binary/Hex.class'
      lacks_entry "$entries" 'org/apache/http/client/HttpClient.class'
      has_entry "$entries" 'org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class'
      lacks_entry "$entries" 'org/apache/commons/compress/archivers/tar/TarArchiveEntry.class'
      ;;
    example-spring-boot-app)
      verify_no_spring_whole_artifact_drops "$fixture_dir"
      has_pattern "$entries" 'BOOT-INF/lib/spring-webmvc-[^/]+\.jar'
      has_entry "$entries" 'META-INF/sbom/application.cdx.json'
      has_entry "$entries" 'META-INF/native-image/sbom.json'
      has_pattern "$entries" 'BOOT-INF/lib/commons-codec-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/snakeyaml-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/spring-context-support-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.mail-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/jakarta.activation-api-[^/]+\.jar'
      has_pattern "$entries" 'BOOT-INF/lib/angus-activation-[^/]+\.jar'
      ;;
    example-cve-unused-app)
      has_entry "$entries" 'com/fasterxml/jackson/databind/ObjectMapper.class'
      has_entry "$entries" 'org/apache/commons/text/similarity/LevenshteinDistance.class'
      lacks_entry "$entries" 'org/apache/commons/text/lookup/StringLookup.class'
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      has_entry "$entries" 'org/codehaus/janino/ClassBodyEvaluator.class'
      has_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      has_prefix "$entries" 'org/codehaus/commons/compiler/'
      has_prefix "$entries" 'org/springframework/'
      ;;
    example-cve-safe-class-app)
      has_entry "$entries" 'ch/qos/logback/classic/Logger.class'
      lacks_entry "$entries" 'org/codehaus/janino/ClassBodyEvaluator.class'
      lacks_entry "$entries" 'org/codehaus/janino/ExpressionEvaluator.class'
      ;;
  esac
}

verify_effective_graph_report() {
  local fixture_dir=$1
  local expected_drops=${2:-}
  local report="$fixture_dir/target/dependency-elider-report.json"
  test -f "$report"
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-effective-graph-report "$report" "$expected_drops"
}

verify_cve_report() {
  local fixture=$1
  local fixture_dir=$2
  local report_output=$3
  local report_json="$fixture_dir/target/dependency-elider-report.json"
  test -f "$report_json"
  test -f "$report_output"
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-cve-report "$fixture" "$report_json" "$report_output"
}

verify_no_spring_whole_artifact_drops() {
  local report="$1/target/dependency-elider-report.json"
  test -f "$report"
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-no-whole-artifact-drops "Spring fixture" "$report"
}

verify_no_cve_whole_artifact_drops() {
  local report="$1/target/dependency-elider-report.json"
  test -f "$report"
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-no-whole-artifact-drops "CVE fixture" "$report"
}

verify_basic_trimmed_artifacts() {
  local fixture_dir=$1
  local shaded_jar=$2
  local original_compress=$3
  local baseline_package_bytes=$4
  local trimmed_compress
  trimmed_compress=$(basic_trimmed_compress_path "$fixture_dir")
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

basic_trimmed_compress_path() {
  local fixture_dir=$1
  local generations="$fixture_dir/target/elided-artifacts/.generations"
  local -a matches=()
  if [[ -d $generations ]]; then
    mapfile -t matches < <(
      find "$generations" -mindepth 2 -maxdepth 2 -type f \
        -name 'org.apache.commons-commons-compress-1.28.0-trimmed.jar' -print
    )
  fi
  if [[ ${#matches[@]} -ne 1 ]]; then
    echo "Expected one committed Commons Compress generation under $generations" >&2
    return 1
  fi
  printf '%s\n' "${matches[0]}"
}

verify_basic_shade_input_paths() {
  local fixture_dir=$1
  local observed="$fixture_dir/target/dependency-elider-shade-inputs.txt"
  local report="$fixture_dir/target/dependency-elider-report.json"
  local trimmed
  trimmed=$(basic_trimmed_compress_path "$fixture_dir")
  test -f "$observed"
  test -f "$report"
  test -f "$trimmed"
  grep -Fq -- "$trimmed" "$observed" || {
    echo "The same-session MavenProject classpath before Shade does not contain trimmed Compress: $observed" >&2
    exit 1
  }
  verify_effective_graph_report "$fixture_dir"
  "$java" --class-path "$support_classpath" ExampleSupport \
    verify-basic-graph-drop "$report" \
      "commons-codec:commons-codec:jar:1.19.0 (compile)" \
      "org.apache.httpcomponents:httpclient:jar:4.3.4 (compile)"
  grep -Fq -- 'commons-codec:commons-codec:jar:1.19.0 (compile)' "$report" || {
    echo "The report must record the raw Commons Codec candidate for comparison: $report" >&2
    exit 1
  }
  grep -Fq -- 'org.apache.httpcomponents:httpclient:jar:4.3.4 (compile)' "$report" || {
    echo "The report must record the raw HttpClient candidate for comparison: $report" >&2
    exit 1
  }
  if grep -Fq -- '/commons-codec/commons-codec/' "$observed" || grep -Fq -- '/org/apache/httpcomponents/httpclient/' "$observed"; then
    echo "The same-session Maven classpath still contains effectively dropped dependencies: $observed" >&2
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
