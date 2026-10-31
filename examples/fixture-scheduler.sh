#!/usr/bin/env bash
# WHY: Provides bounded, evidence-preserving fixture workers with process-group cleanup.

validate_example_jobs() {
  local value=${1-2}
  if [[ ! $value =~ ^[0-9]+$ || $value =~ ^0+$ ]]; then
    echo "EXAMPLE_JOBS must be a positive integer: $value" >&2
    return 2
  fi
}

_run_fixture_worker_child() (
  local status_file=$1
  local worker_function=$2
  local fixture=$3
  trap 'worker_status=$?; printf "%s\\n" "$worker_status" >"$status_file"; exit "$worker_status"' EXIT
  set -e
  "$worker_function" "$fixture"
)

_stop_fixture_workers() {
  local signal=$1
  local pid
  _fixture_interrupted=1
  if [[ $_fixture_signal_status -eq 0 ]]; then
    case $signal in
      INT) _fixture_signal_status=130 ;;
      TERM) _fixture_signal_status=143 ;;
    esac
  fi
  _fixture_next=${#_fixture_names[@]}
  for pid in "${!_fixture_pids[@]}"; do
    kill -TERM -- "-$pid" 2>/dev/null || true
  done
  if [[ $_fixture_launch_pending == true && -n $_fixture_launch_pid ]]; then
    kill -TERM -- "-$_fixture_launch_pid" 2>/dev/null || true
  fi
  for pid in "${!_fixture_pids[@]}"; do
    kill -KILL -- "-$pid" 2>/dev/null || true
  done
  if [[ $_fixture_launch_pending == true && -n $_fixture_launch_pid ]]; then
    kill -KILL -- "-$_fixture_launch_pid" 2>/dev/null || true
  fi
}

_record_fixture_worker() {
  local completed_pid=$1
  local wait_status=$2
  local index=${_fixture_pids[$completed_pid]}
  local fixture=${_fixture_names[index]}
  local status_file="$evidence_dir/$fixture.worker.status"
  local worker_status

  if [[ -s $status_file ]]; then
    worker_status=$(<"$status_file")
  else
    worker_status=$wait_status
    printf '%s\n' "$worker_status" >"$status_file"
  fi
  _fixture_statuses[index]=$worker_status
  unset '_fixture_pids[$completed_pid]'
  _fixture_active=$((_fixture_active - 1))
  if ((worker_status != 0)); then
    _fixture_failures=$((_fixture_failures + 1))
  fi
}

run_fixture_workers() {
  local jobs=$1
  local evidence_dir=$2
  shift 2
  local -a _fixture_names=("$@")
  local -A _fixture_pids=()
  local -a _fixture_statuses=()
  local _fixture_next=0
  local _fixture_active=0
  local _fixture_failures=0
  local _fixture_interrupted=0
  local _fixture_signal_status=0
  local _fixture_launch_pending=false
  local _fixture_launch_pid=
  local _fixture_monitor_was_enabled=false
  local fixture pid completed_pid worker_status wait_status index log_file status_file
  local worker_function=run_fixture_worker

  ((${#_fixture_names[@]} == 0)) && return 0
  while [[ $jobs == 0* && ${#jobs} -gt 1 ]]; do
    jobs=${jobs#0}
  done
  if ((${#jobs} > 9)); then
    jobs=${#_fixture_names[@]}
  elif ((jobs > ${#_fixture_names[@]})); then
    jobs=${#_fixture_names[@]}
  fi
  [[ $- == *m* ]] && _fixture_monitor_was_enabled=true
  set -m
  trap '_stop_fixture_workers INT' INT
  trap '_stop_fixture_workers TERM' TERM

  while ((_fixture_next < ${#_fixture_names[@]} || _fixture_active > 0)); do
    while ((_fixture_next < ${#_fixture_names[@]} && _fixture_active < jobs && !_fixture_interrupted)); do
      index=$_fixture_next
      fixture=${_fixture_names[index]}
      log_file="$evidence_dir/$fixture.worker.log"
      status_file="$evidence_dir/$fixture.worker.status"
      rm -f -- "$status_file"
      # WHY: A signal can run between the asynchronous launch and PID registration.
      _fixture_launch_pid=
      _fixture_launch_pending=true
      _run_fixture_worker_child "$status_file" "$worker_function" "$fixture" \
        >"$log_file" 2>&1 &
      _fixture_launch_pid=$!
      pid=$_fixture_launch_pid
      _fixture_pids[$pid]=$index
      _fixture_launch_pending=false
      if ((_fixture_interrupted != 0)); then
        kill -TERM -- "-$pid" 2>/dev/null || true
        kill -KILL -- "-$pid" 2>/dev/null || true
      fi
      _fixture_next=$((_fixture_next + 1))
      _fixture_active=$((_fixture_active + 1))
    done

    if ((_fixture_active > 0)); then
      completed_pid=
      if wait -n -p completed_pid "${!_fixture_pids[@]}"; then
        wait_status=0
      else
        wait_status=$?
      fi
      if [[ -n ${completed_pid:-} && ${_fixture_pids[${completed_pid:-}]+present} ]]; then
        _record_fixture_worker "$completed_pid" "$wait_status"
      elif ((wait_status == 127)); then
        # WHY: A signal handler can kill all workers while wait -n is active;
        # Bash then returns 127 without naming a child, so collect each tracked
        # PID explicitly to prevent spinning on a stale active count.
        for pid in "${!_fixture_pids[@]}"; do
          if wait "$pid"; then
            wait_status=0
          else
            wait_status=$?
          fi
          _record_fixture_worker "$pid" "$wait_status"
        done
      fi
    fi
  done

  trap - INT TERM
  if [[ $_fixture_monitor_was_enabled == false ]]; then
    set +m
  fi
  for index in "${!_fixture_names[@]}"; do
    fixture=${_fixture_names[index]}
    log_file="$evidence_dir/$fixture.worker.log"
    status_file="$evidence_dir/$fixture.worker.status"
    if [[ ${_fixture_statuses[index]+present} ]]; then
      worker_status=${_fixture_statuses[index]}
    else
      worker_status=not-started
      : >"$log_file"
      printf '%s\n' "$worker_status" >"$status_file"
      _fixture_statuses[index]=$worker_status
    fi
    printf '\n===== %s (status %s) =====\n' "$fixture" "$worker_status"
    cat -- "$log_file"
    printf '===== end %s (status %s) =====\n' "$fixture" "$worker_status"
  done

  if ((_fixture_interrupted != 0)); then
    return "$_fixture_signal_status"
  fi
  if ((_fixture_failures != 0)); then
    printf '%s standalone fixture worker(s) failed; see ordered worker logs above and evidence in %s\n' \
      "$_fixture_failures" "$evidence_dir" >&2
    return 1
  fi
}
