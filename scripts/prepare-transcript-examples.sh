#!/usr/bin/env bash
# WHY: Prepares example artifacts and runtime traces for transcripts; the safe-class fixture compiles test sources so its complete provider inventory can be proven.
set -euo pipefail

main() {
  repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  cd -- "$repo_root"

  maven=${MAVEN:-"$repo_root/mvnw"}
  maven_args=${MAVEN_ARGS:---batch-mode --no-transfer-progress}
  app_timeout=${TRANSCRIPT_APP_TIMEOUT:-30s}
  if [[ $maven != /* ]]; then
    if [[ $maven == */* ]]; then
      maven="$repo_root/$maven"
    else
      maven=$(command -v "$maven")
    fi
  fi
  if [[ -z ${JAVA_HOME:-} ]]; then
    echo "JAVA_HOME must point to a supported JDK; transcripts currently target Java 21" >&2
    exit 2
  fi
  java_home=$JAVA_HOME
  if [[ $java_home != /* ]]; then
    java_home="$repo_root/$java_home"
  fi
  java="$java_home/bin/java"
  if [[ ! -x $maven || ! -x $java ]] || ! command -v timeout >/dev/null || ! command -v curl >/dev/null; then
    echo "Maven, Java, timeout, or curl executable is missing" >&2
    exit 2
  fi
  read -r -a maven_options <<<"$maven_args"

  mkdir -p -- "$repo_root/.scratch"
  evidence_dir=$(mktemp -d "$repo_root/.scratch/maven-dependency-elider-examples.transcript.XXXXXX")
  cache_dir="$evidence_dir/vulnerability-cache"
  mkdir -p -- "$cache_dir"
  cp -- "$repo_root/scripts/fixtures/transcript-vulnerability-cache/index.json" "$cache_dir/index.json"
  active_process_pid=""
  cleanup() {
    local status=$?
    if [[ -n ${active_process_pid:-} ]]; then
      kill -TERM "$active_process_pid" 2>/dev/null || true
      wait "$active_process_pid" 2>/dev/null || true
    fi
    printf 'Transcript evidence retained at %s\n' "$evidence_dir" >&2
    return "$status"
  }
  trap cleanup EXIT

  "$maven" "${maven_options[@]}" -f "$repo_root/pom.xml" \
    -pl dependency-elider-maven-plugin -am install -Dmaven.test.skip=true

  run_fixture_maven() {
    local fixture_dir=$1
    shift
    (cd -- "$fixture_dir" && "$maven" "${maven_options[@]}" "$@")
  }

  fixture_names=(
    example-basic-app
    example-spring-boot-app
    example-cve-unused-app
    example-cve-safe-class-app
  )

  wait_for_spring_endpoint() {
    local process_id=$1
    local log_file=$2
    local response_file=$3
    local port
    local http_status
    local response
    while kill -0 "$process_id" 2>/dev/null; do
      port=$(sed -nE 's/.*Tomcat started on port ([0-9]+) \(http\).*/\1/p' "$log_file" | tail -n 1)
      if [[ -n $port ]]; then
        http_status=$(curl --silent --show-error --connect-timeout 1 --max-time 2 \
          --output "$response_file" --write-out '%{http_code}' \
          "http://127.0.0.1:$port/api/hello" 2>/dev/null || true)
        response=""
        if [[ -f $response_file ]]; then
          response=$(<"$response_file")
        fi
        if [[ $http_status == 200 && $response == '{"message":"hello"}' ]]; then
          return 0
        fi
      fi
      sleep 0.2
    done
    return 1
  }
  export -f wait_for_spring_endpoint

  for fixture in "${fixture_names[@]}"; do
    fixture_dir="$repo_root/examples/$fixture"
    jar_file="$fixture_dir/target/$fixture-0.1.0-SNAPSHOT.jar"
    trace="$evidence_dir/$fixture.log"

    run_fixture_maven "$fixture_dir" clean package \
      -Dmaven.test.skip=true -Delide.mode=baseline
    if [[ ! -f $jar_file ]]; then
      echo "Baseline package was not created: $jar_file" >&2
      exit 1
    fi

    if [[ $fixture == example-spring-boot-app ]]; then
      production_output="$evidence_dir/$fixture-production-classes"
      cp -a -- "$fixture_dir/target/classes" "$production_output"
      spring_log="$evidence_dir/$fixture-startup.log"
      response_file="$evidence_dir/$fixture-endpoint-response.json"
      "$java" "-Xlog:class+load=info:file=$trace" "-Djava.io.tmpdir=$evidence_dir" \
        -jar "$jar_file" --server.port=0 >"$spring_log" 2>&1 &
      active_process_pid=$!
      status=0
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        bash -c 'wait_for_spring_endpoint "$@"' _ "$active_process_pid" "$spring_log" "$response_file" || status=$?
      if [[ $status -ne 0 ]]; then
        kill -TERM "$active_process_pid" 2>/dev/null || true
        wait "$active_process_pid" 2>/dev/null || true
        active_process_pid=""
        cat -- "$spring_log" >&2
        echo "Spring Boot endpoint did not return HTTP 200 with the expected body before readiness timeout (status $status)" >&2
        exit 1
      fi
      kill -TERM "$active_process_pid" 2>/dev/null || true
      wait "$active_process_pid" 2>/dev/null || true
      active_process_pid=""
    else
      timeout --signal=TERM --kill-after=5s "$app_timeout" \
        "$java" "-Xlog:class+load=info:file=$trace" "-Djava.io.tmpdir=$evidence_dir" \
        -jar "$jar_file" >"$evidence_dir/$fixture-startup.log" 2>&1
    fi
    if [[ ! -s $trace ]]; then
      echo "Runtime trace was not created: $trace" >&2
      exit 1
    fi
  done

  for fixture in "${fixture_names[@]}"; do
    fixture_dir="$repo_root/examples/$fixture"
    trace="$evidence_dir/$fixture.log"
    elision_options=(
      --offline
      "-Delide.cveCacheDirectory=$cache_dir"
      -Delide.mode=elision
      "-Delide.traceFiles=$trace"
      -Delide.trimJars=true
      -Delide.sourceRootsComplete=true
      -Dmaven.compiler.proc=none
    )
    if [[ $fixture == example-cve-safe-class-app ]]; then
      elision_options+=(-DskipTests=true)
    else
      elision_options+=(-Dmaven.test.skip=true)
    fi
    case "$fixture" in
      example-basic-app)
        elision_options+=(
          -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
        )
        ;;
      example-spring-boot-app)
        elision_options+=(
          "-Delide.productionOutput=$evidence_dir/$fixture-production-classes"
          -Delide.trimRoots=freemarker.template.Configuration,groovy.text.markup.MarkupTemplateEngine,jakarta.validation.Validation,org.webjars.WebJarAssetLocator,org.reactivestreams.Publisher,io.micrometer.context.ContextSnapshot,reactor.core.publisher.Flux,reactor.core.publisher.Mono,reactor.util.context.Context,jakarta.servlet.jsp.jstl.core.Config,javax.annotation.Nonnull,edu.umd.cs.findbugs.annotations.SuppressFBWarnings,com.thoughtworks.xstream.XStream,com.thoughtworks.xstream.io.xml.StaxDriver
          -Delide.trimSkipArtifacts=org.springframework.boot:spring-boot:3.3.5:jar:,org.springframework.boot:spring-boot-autoconfigure:3.3.5:jar:,org.springframework.boot:spring-boot-actuator:3.3.5:jar:,org.springframework.boot:spring-boot-actuator-autoconfigure:3.3.5:jar:,org.springframework:spring-web:6.1.14:jar:,org.springframework:spring-context:6.1.14:jar:,org.springframework:spring-context-support:6.1.14:jar:,org.springframework:spring-beans:6.1.14:jar:,org.springframework:spring-aop:6.1.14:jar:,org.springframework:spring-expression:6.1.14:jar:,org.springframework:spring-core:6.1.14:jar:,io.projectreactor:reactor-core:3.6.11:jar:,io.micrometer:micrometer-core:1.13.6:jar:,io.micrometer:micrometer-observation:1.13.6:jar:,io.micrometer:micrometer-commons:1.13.6:jar:,io.micrometer:micrometer-jakarta9:1.13.6:jar:,org.apache.groovy:groovy-templates:4.0.23:jar:
        )
        ;;
      example-cve-unused-app|example-cve-safe-class-app)
        elision_options+=(
          -Delide.trimSkipArtifacts=org.springframework:spring-context:6.2.7:jar:,org.springframework:spring-beans:6.2.7:jar:,org.springframework:spring-aop:6.2.7:jar:,org.springframework:spring-expression:6.2.7:jar:,org.springframework:spring-core:6.2.7:jar:,org.springframework:spring-jcl:6.2.7:jar:,io.micrometer:micrometer-observation:1.15.0:jar:,io.micrometer:micrometer-commons:1.15.0:jar:
        )
        ;;
      *)
        echo "Unsupported transcript fixture: $fixture" >&2
        exit 2
        ;;
    esac
    run_fixture_maven "$fixture_dir" clean package "${elision_options[@]}"
  done

}

main "$@"
