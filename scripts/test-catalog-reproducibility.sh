#!/usr/bin/env bash
# WHY: Keeps the catalog digest stable in generated transcripts by checking repeated Maven packaging.
set -euo pipefail

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum executable is missing" >&2
    return 2
  fi
}

main() {
  repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  cd -- "$repo_root"

  maven=${MAVEN:-"$repo_root/mvnw"}
  maven_args=${MAVEN_ARGS:---batch-mode --no-transfer-progress}
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
    jar="$java_home/bin/jar"
  else
    jar=$(command -v jar || true)
  fi
  if [[ ! -x $maven || -z $jar || ! -x $jar ]] || { ! command -v sha256sum >/dev/null && ! command -v shasum >/dev/null; }; then
    echo "Maven, jar, or sha256sum/shasum executable is missing" >&2
    exit 2
  fi
  read -r -a maven_options <<<"$maven_args"

  pom="$repo_root/examples/logback-vulnerability-mapping-catalog/pom.xml"
  archive="$repo_root/examples/logback-vulnerability-mapping-catalog/target/logback-vulnerability-mapping-catalog-1.0.0.jar"
  manifest_dir=$(mktemp -d)
  trap 'rm -rf -- "$manifest_dir"' EXIT
  "$maven" "${maven_options[@]}" -f "$pom" clean package -DskipTests
  first_digest=$(sha256_file "$archive")
  sleep 2
  "$maven" "${maven_options[@]}" -f "$pom" clean package -DskipTests
  second_digest=$(sha256_file "$archive")

  (cd -- "$manifest_dir" && "$jar" -xf "$archive" META-INF/MANIFEST.MF)
  if grep -Eq '^Build-Jdk(-Spec)?:' "$manifest_dir/META-INF/MANIFEST.MF"; then
    echo "Catalog manifest must not encode the build JDK" >&2
    exit 1
  fi

  if [[ $first_digest != "$second_digest" ]]; then
    printf 'Catalog package is not reproducible: %s then %s\n' \
      "$first_digest" "$second_digest" >&2
    exit 1
  fi
  printf 'Catalog package SHA-256 is reproducible: %s\n' "$second_digest"
}

main "$@"
