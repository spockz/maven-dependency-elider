#!/usr/bin/env bash
# WHY: Proves fixture scheduling, ordered evidence, aggregate failures, and process cleanup without timing assumptions.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/examples/fixture-scheduler.sh"
test_root=$(mktemp -d)
test_scheduler_pids=()
cleanup_test_root() {
  local exit_status=${1:-0}
  local cleanup_status=0
  local scheduler_pid
  trap - EXIT
  set +e
  for scheduler_pid in "${test_scheduler_pids[@]}"; do
    kill -TERM "$scheduler_pid" 2>/dev/null
  done
  for scheduler_pid in "${test_scheduler_pids[@]}"; do
    wait "$scheduler_pid" 2>/dev/null
    if kill -0 "$scheduler_pid" 2>/dev/null; then
      cleanup_status=1
    fi
  done
  if [[ -n ${TEST_ROOT_MARKER:-} ]]; then
    if ! printf '%s\n' "$test_root" >"$TEST_ROOT_MARKER"; then
      cleanup_status=1
    fi
  fi
  if [[ ${KEEP_TEST_ROOT:-false} == true ]]; then
    if ! printf 'test evidence: %s\n' "$test_root"; then
      cleanup_status=1
    fi
  else
    if ! rm -rf -- "$test_root"; then
      cleanup_status=1
    fi
  fi
  if ((exit_status == 0 && cleanup_status != 0)); then
    return 1
  fi
  return "$exit_status"
}
exit_cleanup_test_root() {
  local exit_status=$?
  local final_status=$exit_status
  trap - EXIT
  if cleanup_test_root "$exit_status"; then
    final_status=$?
  else
    final_status=$?
  fi
  exit "$final_status"
}
trap exit_cleanup_test_root EXIT
export TEST_ROOT=$test_root

track_test_scheduler() {
  test_scheduler_pids+=("$1")
}

forget_test_scheduler() {
  local scheduler_pid=$1
  local index
  for index in "${!test_scheduler_pids[@]}"; do
    if [[ ${test_scheduler_pids[index]} == "$scheduler_pid" ]]; then
      unset 'test_scheduler_pids[index]'
    fi
  done
}

record_worker_activity() {
  local delta=$1
  local active peak
  exec 8>>"$TEST_ROOT/activity.lock"
  flock -x 8
  active=$(<"$TEST_ROOT/active")
  active=$((active + delta))
  printf '%s\n' "$active" >"$TEST_ROOT/active"
  peak=$(<"$TEST_ROOT/peak")
  if ((active > peak)); then
    printf '%s\n' "$active" >"$TEST_ROOT/peak"
  fi
  flock -u 8
  exec 8>&-
}

run_fixture_worker() {
  local fixture=$1
  record_worker_activity 1
  if [[ -p $TEST_ROOT/started-$fixture ]]; then
    printf '%s\n' "$fixture" >"$TEST_ROOT/started-$fixture"
  else
    printf '%s\n' "$fixture" >"$TEST_ROOT/started"
  fi
  if [[ -p $TEST_ROOT/release-$fixture ]]; then
    IFS= read -r _ <"$TEST_ROOT/release-$fixture"
  fi
  printf 'ran:%s\n' "$fixture"
  record_worker_activity -1
  [[ $fixture != fail-* ]]
}

assert_ordered_logs() {
  local output=$1
  shift
  local fixture
  local previous=0
  local line
  for fixture in "$@"; do
    line=$(grep -n "===== $fixture (status " "$output" | cut -d: -f1)
    if ((line <= previous)); then
      echo "Worker logs were not replayed in fixture-list order: $fixture" >&2
      return 1
    fi
    previous=$line
  done
}

test_overlap_limit_and_log_order() {
  local output="$TEST_ROOT/ordered.log"
  local scheduler_pid fixture
  local -a fixtures=(first second third fourth)
  mkdir -p -- "$TEST_ROOT/evidence"
  printf '0\n' >"$TEST_ROOT/active"
  printf '0\n' >"$TEST_ROOT/peak"
  local fixture
  for fixture in "${fixtures[@]}"; do
    mkfifo "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
  done
  run_fixture_workers 2 "$TEST_ROOT/evidence" "${fixtures[@]}" >"$output" 2>&1 &
  scheduler_pid=$!
  track_test_scheduler "$scheduler_pid"
  for fixture in first second; do
    IFS= read -r _ <"$TEST_ROOT/started-$fixture"
  done
  if [[ $(<"$TEST_ROOT/peak") != 2 ]]; then
    echo "Two workers did not overlap at the synchronization barrier" >&2
    return 1
  fi
  for fixture in first second; do
    printf 'release\n' >"$TEST_ROOT/release-$fixture"
  done
  for fixture in third fourth; do
    IFS= read -r _ <"$TEST_ROOT/started-$fixture"
    printf 'release\n' >"$TEST_ROOT/release-$fixture"
  done
  if wait "$scheduler_pid"; then
    :
  else
    echo "Successful fixture workers returned a failure status" >&2
    return 1
  fi
  forget_test_scheduler "$scheduler_pid"
  for fixture in "${fixtures[@]}"; do
    rm -f -- "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
  done
  if (( $(<"$TEST_ROOT/peak") > 2 )); then
    echo "Worker scheduler exceeded its limit of two" >&2
    return 1
  fi
  assert_ordered_logs "$output" "${fixtures[@]}"
}

test_failure_aggregation() {
  local evidence="$TEST_ROOT/failures"
  local output="$TEST_ROOT/failures.log"
  local status fixture failures
  local -a fixtures=(fail-one fail-two fail-three)
  mkdir -p -- "$evidence"
  set +e
  run_fixture_workers 2 "$evidence" "${fixtures[@]}" >"$output" 2>&1
  status=$?
  set -e
  if ((status == 0)); then
    echo "Fixture failures were not reported" >&2
    return 1
  fi
  failures=$(grep -c 'ran:fail-' "$output")
  if ((failures != ${#fixtures[@]})); then
    echo "Not every failed fixture completed: expected ${#fixtures[@]}, observed $failures" >&2
    return 1
  fi
  for fixture in "${fixtures[@]}"; do
    test "$(<"$evidence/$fixture.worker.status")" -ne 0
  done
  assert_ordered_logs "$output" "${fixtures[@]}"
}

test_early_worker_failure() {
  local evidence="$TEST_ROOT/early-failure-evidence"
  local output="$TEST_ROOT/early-failure.log"
  local status
  mkdir -p -- "$evidence"
  run_fixture_worker() {
    local fixture=$1
    if [[ $fixture == fail-early ]]; then
      false
      touch "$TEST_ROOT/after-early-failure"
    fi
    printf 'ran:%s\n' "$fixture"
  }
  set +e
  run_fixture_workers 1 "$evidence" fail-early independent >"$output" 2>&1
  status=$?
  set -e
  if ((status == 0)); then
    echo "An early fixture failure was reported as success" >&2
    return 1
  fi
  test ! -e "$TEST_ROOT/after-early-failure"
  test "$(<"$evidence/fail-early.worker.status")" -ne 0
  test "$(<"$evidence/independent.worker.status")" = 0
  grep -Fq 'ran:independent' "$output"
  assert_ordered_logs "$output" fail-early independent
}

test_interrupted_queued_workers() {
  local evidence output scheduler_pid fixture status signal expected_status
  run_fixture_worker() {
    local name=$1
    printf '%s\n' "$name" >"$TEST_ROOT/started-$name"
    IFS= read -r _ <"$TEST_ROOT/release-$name"
  }
  for signal in TERM INT; do
    evidence="$TEST_ROOT/interrupted-$signal-evidence"
    output="$TEST_ROOT/interrupted-$signal.log"
    mkdir -p -- "$evidence"
    for fixture in first second third; do
      mkfifo "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
    done
    run_fixture_workers 1 "$evidence" first second third >"$output" 2>&1 &
    scheduler_pid=$!
    track_test_scheduler "$scheduler_pid"
    IFS= read -r fixture <"$TEST_ROOT/started-first"
    test "$fixture" = first
    kill -"$signal" "$scheduler_pid"
    set +e
    wait "$scheduler_pid"
    status=$?
    set -e
    forget_test_scheduler "$scheduler_pid"
    expected_status=143
    [[ $signal == INT ]] && expected_status=130
    if ((status != expected_status)); then
      echo "Queued-fixture SIG$signal returned $status instead of $expected_status" >&2
      cat "$output" >&2
      return 1
    fi
    test "$(<"$evidence/first.worker.status")" -ne 0
    test "$(<"$evidence/second.worker.status")" = not-started
    test "$(<"$evidence/third.worker.status")" = not-started
    test -f "$evidence/second.worker.log"
    test -f "$evidence/third.worker.log"
    assert_ordered_logs "$output" first second third
    for fixture in first second third; do
      rm -f -- "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
    done
  done
}

test_interrupted_active_workers() {
  local evidence="$TEST_ROOT/interrupted-active-evidence"
  local output="$TEST_ROOT/interrupted-active.log"
  local scheduler_pid fixture status worker_pid worker_pgid
  local -a active_fixtures=(active-one active-two queued-three)
  mkdir -p -- "$evidence"
  for fixture in "${active_fixtures[@]}"; do
    mkfifo "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
  done
  run_fixture_worker() {
    local name=$1
    local process_group
    process_group=$(ps -o pgid= -p "$BASHPID" | tr -d ' ')
    printf '%s %s\n' "$BASHPID" "$process_group" >"$TEST_ROOT/$name.identity"
    printf '%s\n' "$name" >"$TEST_ROOT/started-$name"
    IFS= read -r _ <"$TEST_ROOT/release-$name"
  }
  run_fixture_workers 2 "$evidence" "${active_fixtures[@]}" >"$output" 2>&1 &
  scheduler_pid=$!
  track_test_scheduler "$scheduler_pid"
  for fixture in active-one active-two; do
    IFS= read -r _ <"$TEST_ROOT/started-$fixture"
  done
  kill -TERM "$scheduler_pid"
  set +e
  wait "$scheduler_pid"
  status=$?
  set -e
  forget_test_scheduler "$scheduler_pid"
  if ((status != 143)); then
    echo "SIGTERM with two active workers returned $status instead of 143" >&2
    cat "$output" >&2
    return 1
  fi
  for fixture in active-one active-two; do
    test "$(<"$evidence/$fixture.worker.status")" -ne 0
    read -r worker_pid worker_pgid <"$TEST_ROOT/$fixture.identity"
    if ps -eo pgid= | awk -v group="$worker_pgid" '$1 == group { found=1 } END { exit !found }'; then
      echo "Interrupted worker process group $worker_pgid survived" >&2
      return 1
    fi
    rm -f -- "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
  done
  test "$(<"$evidence/queued-three.worker.status")" = not-started
  rm -f -- "$TEST_ROOT/started-queued-three" "$TEST_ROOT/release-queued-three"
  assert_ordered_logs "$output" "${active_fixtures[@]}"
}

run_cleanup_probe() {
  local evidence="$TEST_ROOT/cleanup-probe-evidence"
  local scheduler_pid fixture
  mkdir -p -- "$evidence"
  for fixture in cleanup-one cleanup-two; do
    mkfifo "$TEST_ROOT/started-$fixture" "$TEST_ROOT/release-$fixture"
  done
  run_fixture_worker() {
    local name=$1
    local process_group
    process_group=$(ps -o pgid= -p "$BASHPID" | tr -d ' ')
    printf 'worker %s %s\n' "$BASHPID" "$process_group" >>"$CLEANUP_OBSERVATION"
    printf '%s\n' "$name" >"$TEST_ROOT/started-$name"
    IFS= read -r _ <"$TEST_ROOT/release-$name"
  }
  run_fixture_workers 2 "$evidence" cleanup-one cleanup-two >"$TEST_ROOT/cleanup-probe.log" 2>&1 &
  scheduler_pid=$!
  track_test_scheduler "$scheduler_pid"
  local scheduler_group
  scheduler_group=$(ps -o pgid= -p "$scheduler_pid" | tr -d ' ')
  printf 'scheduler %s %s\n' "$scheduler_pid" "$scheduler_group" >>"$CLEANUP_OBSERVATION"
  for fixture in cleanup-one cleanup-two; do
    IFS= read -r _ <"$TEST_ROOT/started-$fixture"
  done
  false
}

test_exit_cleanup_reaps_workers() {
  local observation="$TEST_ROOT/cleanup-observation"
  local root_marker="$TEST_ROOT/cleanup-root"
  local output="$TEST_ROOT/cleanup-probe-wrapper.log"
  local status test_root_path role process_id process_group
  set +e
  SCHEDULER_CLEANUP_PROBE=true CLEANUP_OBSERVATION="$observation" TEST_ROOT_MARKER="$root_marker" \
    KEEP_TEST_ROOT=false bash "$repo_root/examples/test-fixture-scheduler.sh" >"$output" 2>&1
  status=$?
  set -e
  if ((status != 1)); then
    echo "Cleanup probe returned $status instead of its intentional status 1" >&2
    cat "$output" >&2
    return 1
  fi
  test -s "$observation"
  test -s "$root_marker"
  test_root_path=$(<"$root_marker")
  if [[ -e $test_root_path ]]; then
    echo "EXIT cleanup removed its test root incompletely: $test_root_path" >&2
    return 1
  fi
  while read -r role process_id process_group; do
    if kill -0 "$process_id" 2>/dev/null; then
      echo "EXIT cleanup left $role PID $process_id alive" >&2
      return 1
    fi
    if [[ $role == worker ]] && ps -eo pgid= | \
      awk -v group="$process_group" '$1 == group { found=1 } END { exit !found }'; then
      echo "EXIT cleanup left $role PID $process_id or process group $process_group alive" >&2
      return 1
    fi
  done <"$observation"
}

test_descendant_cleanup() {
  local evidence="$TEST_ROOT/descendant-evidence"
  local output="$TEST_ROOT/descendant.log"
  local scheduler_pid child_pid child_pgid worker_pid worker_pgid status
  cleanup_descendant_groups() {
    local group
    for group in "$worker_pgid" "$child_pgid"; do
      kill -TERM -- "-$group" 2>/dev/null || true
    done
    for group in "$worker_pgid" "$child_pgid"; do
      kill -KILL -- "-$group" 2>/dev/null || true
    done
  }
  mkdir -p -- "$evidence"
  mkfifo "$TEST_ROOT/descendant-start" "$TEST_ROOT/descendant-release"
  run_fixture_worker() {
    printf '%s %s\n' "$BASHPID" "$(ps -o pgid= -p "$BASHPID" | tr -d ' ')" \
      >"$TEST_ROOT/worker.identity"
    timeout --foreground --signal=TERM --kill-after=1s 1h bash -c \
      'child_pid=$BASHPID; printf "%s %s\\n" "$child_pid" "$(ps -o pgid= -p "$child_pid" | tr -d " ")" >"$TEST_ROOT/child.identity"; printf "child\\n" >"$TEST_ROOT/descendant-start"; IFS= read -r _ <"$TEST_ROOT/descendant-release"'
  }
  run_fixture_workers 1 "$evidence" descendant >"$output" 2>&1 &
  scheduler_pid=$!
  IFS= read -r _ <"$TEST_ROOT/descendant-start"
  read -r child_pid child_pgid <"$TEST_ROOT/child.identity"
  read -r worker_pid worker_pgid <"$TEST_ROOT/worker.identity"
  if [[ $child_pgid != "$worker_pgid" ]]; then
    kill -TERM "$scheduler_pid"
    cleanup_descendant_groups
    set +e
    wait "$scheduler_pid"
    set -e
    echo "Foreground timeout process group $child_pgid did not match worker group $worker_pgid (PID $worker_pid)" >&2
    return 1
  fi
  kill -TERM "$scheduler_pid"
  set +e
  wait "$scheduler_pid"
  status=$?
  set -e
  if ((status != 143)); then
    cleanup_descendant_groups
    echo "SIGTERM returned $status instead of conventional status 143" >&2
    cat "$output" >&2
    return 1
  fi
  if ps -eo pgid= | awk -v group="$worker_pgid" '$1 == group { found=1 } END { exit !found }'; then
    cleanup_descendant_groups
    echo "Worker process group $worker_pgid survived scheduler interruption" >&2
    return 1
  fi
}

test_invalid_jobs_before_bootstrap() {
  local fake_maven="$TEST_ROOT/fake-maven"
  local output invalid status
  cat >"$fake_maven" <<'MAVEN'
#!/usr/bin/env bash
touch "$TEST_ROOT/maven-started"
MAVEN
  chmod +x "$fake_maven"
  for invalid in 0 '' many; do
    output="$TEST_ROOT/invalid-jobs-${invalid:-empty}.log"
    set +e
    EXAMPLE_JOBS="$invalid" TEST_ROOT="$TEST_ROOT" MAVEN="$fake_maven" JAVA_HOME=/missing \
      "$repo_root/examples/run-elision-cycle.sh" >"$output" 2>&1
    status=$?
    set -e
    if ((status == 0)) || ! grep -Fq 'EXAMPLE_JOBS must be a positive integer' "$output"; then
      echo "Invalid EXAMPLE_JOBS was not rejected before bootstrap: '$invalid'" >&2
      cat "$output" >&2
      return 1
    fi
  done
  test ! -e "$TEST_ROOT/maven-started"
}

if [[ ${SCHEDULER_CLEANUP_PROBE:-false} == true ]]; then
  run_cleanup_probe
  exit 1
fi

test_overlap_limit_and_log_order
test_failure_aggregation
test_early_worker_failure
test_interrupted_queued_workers
test_interrupted_active_workers
test_descendant_cleanup
test_exit_cleanup_reaps_workers
test_invalid_jobs_before_bootstrap
if ! cleanup_test_root 0; then
  trap - EXIT
  echo "Fixture scheduler test cleanup failed." >&2
  exit 1
fi
trap - EXIT
printf 'Fixture scheduler synchronization tests passed.\n'
