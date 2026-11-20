#!/usr/bin/env bash
# WHY: Exercises the packaged runtime downloader, archive handoff, and offline replay.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$1/runtime-preparation
maven=$2
shift 2
options=("$@")
unset MAVEN_ARGS
cd -- "$repo_root"
mkdir -p -- "$work/downloads"
java_home=${JAVA_HOME:?JAVA_HOME must point to a JDK 21+ installation}
pom="$repo_root/examples/example-forbidden-code-app/pom.xml"
plugin=io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT
downloader=org.jreleaser:jdks-maven-plugin:1.26.0:setup-jdks@prepare-elider-runtime

run() {
  local expected=$1 name=$2 status=0
  shift 2
  "$maven" "${options[@]}" "$@" >"$work/$name.log" 2>&1 || status=$?
  if [[ $status != "$expected" ]]; then
    cat -- "$work/$name.log" >&2
    printf 'Expected Maven exit %s, received %s in %s\n' "$expected" "$status" "$name" >&2
    return 1
  fi
}

acquire() {
  local option
  local online=()
  for option in "${options[@]}"; do
    case "$option" in
      -o|--offline) ;;
      *) online+=("$option") ;;
    esac
  done
  local options=("${online[@]}" -nsu)
  run "$@"
}

"$java_home/bin/jlink" --add-modules java.base --strip-debug --output "$work/image"
"$java_home/bin/jar" --create --file "$work/downloads/runtime.zip" \
  -C "$work" image/release -C "$work" image/lib/modules
"$java_home/bin/jlink" --add-modules java.logging --strip-debug --output "$work/alternate-image"
"$java_home/bin/jar" --create --file "$work/downloads/alternate.zip" \
  -C "$work" alternate-image/release -C "$work" alternate-image/lib/modules
go build -o "$work/serve" "$repo_root/examples/support/runtime-download-fixture.go"
"$work/serve" "$work/downloads" "$work/discovery.pem" >"$work/address" 2>"$work/server.log" &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true' EXIT
for attempt in {1..50}; do
  [[ ! -s "$work/address" ]] || break
  kill -0 "$server"
  sleep 0.1
done
address=$(<"$work/address")
[[ $address =~ ^127\.0\.0\.1:[0-9]+$ ]]
url="http://$address"
read -r checksum ignored < <(sha256sum "$work/downloads/runtime.zip")
read -r alternate_checksum ignored < <(sha256sum "$work/downloads/alternate.zip")

source_repository=$("$maven" "${options[@]}" -q -DforceStdout \
  -Dexpression=settings.localRepository help:evaluate)
source_repository=$(printf '%s\n' "$source_repository" | sed $'s/\033\\[[0-9;]*m//g')
[[ -d $source_repository ]]
local_repository="$work/repository"
options+=("-Dmaven.repo.local=$local_repository" "-Dmaven.repo.local.tail=$source_repository")

printf '%s\n' io.github.spockz.example.forbidden.PlainApplication \
  org.apache.commons.compress.archivers.zip.ZipArchiveEntry >"$work/trace.txt"
fixture=(
  -f "$pom" -Dcommons-compress.version=1.18
  "-Dexample.buildDirectory=$work/build" "-Delide.traceFiles=$work/trace.txt"
  "-Delide.cveCacheDirectory=$work/advisories" -Delide.osvSnapshotUri= -Delide.cveListGitUri=
  -Delide.trimJars=true
)
prepare=(
  -Pelide-forbidden-example,prepare-forbidden-runtime -Delider.runtime.platform=linux
  "-Delider.runtime.archiveUrl=$url/runtime.zip" "-Delider.runtime.archiveSha256=$checksum"
)
destination=elider-target-jre/runtime.zip
archive="$work/prepared/$destination"

run 0 inactive "${fixture[@]}" "-Delider.runtime.cacheDirectory=$work/inactive" initialize
test ! -e "$work/inactive/$destination"
acquire 0 prepared "${fixture[@]}" "${prepare[@]}" "-Delider.runtime.cacheDirectory=$work/prepared" process-classes
cmp -- "$archive" "$work/downloads/runtime.zip"
awk '/setup-jdks \(prepare-elider-runtime\)/ {setup = NR}
     /enforce \(check-elider-runtime-archive\)/ {check = NR}
     /:elide \(observe-forbidden-code\)/ {elide = NR}
     END {exit !(setup > 0 && setup < check && check < elide)}' "$work/prepared.log"
grep -Fq "Runtime input $archive: Java" "$work/prepared.log"
sbom="$work/build/dependency-elider-sbom.cdx.json"
grep -Eq '"name"[[:space:]]*:[[:space:]]*"commons-compress"' "$sbom"
if grep -Fq -e 'elider-target-jre' -e "$checksum" "$sbom"; then
  printf 'A preparation input entered the application SBOM\n' >&2
  exit 1
fi

acquire 0 direct "${fixture[@]}" "${prepare[@]}" "-Delider.runtime.cacheDirectory=$work/direct" "$downloader"
cmp -- "$work/direct/$destination" "$archive"
if grep -Eq 'check-elider-runtime-archive|observe-forbidden-code' "$work/direct.log"; then
  printf 'The direct downloader goal executed other lifecycle steps\n' >&2
  exit 1
fi

acquire 1 missing-checksum "${fixture[@]}" -Pprepare-forbidden-runtime -Delider.runtime.platform=linux \
  "-Delider.runtime.archiveUrl=$url/runtime.zip" "-Delider.runtime.cacheDirectory=$work/no-checksum" initialize
grep -Fq 'checksum is missing' "$work/missing-checksum.log"
acquire 1 stale-preparation "${fixture[@]}" -Pprepare-forbidden-runtime -Delider.runtime.platform=linux \
  "-Delider.runtime.archiveUrl=$url/alternate.zip" "-Delider.runtime.archiveSha256=$alternate_checksum" \
  "-Delider.runtime.cacheDirectory=$work/prepared" initialize
grep -Fq 'Invalid checksum' "$work/stale-preparation.log"

offline=(-o "${fixture[@]}" -Pelide-forbidden-example "-Delide.runtimeInputs=$archive,$java_home")
run 0 offline "${offline[@]}" process-classes
grep -Fq "Runtime input $archive: Java" "$work/offline.log"
grep -Fq "Runtime input $java_home: Java" "$work/offline.log"
run 0 warm-offline "${offline[@]}" process-classes
grep -Fq '1 validated hit(s)' "$work/warm-offline.log"
index_dir="$local_repository/.elider-runtime-index"
find "$index_dir" -name '*.json.gz' -type f -printf '%f %s %T@\n' | sort >"$work/index-before-clean"
test -s "$work/index-before-clean"
run 0 clean-offline "${offline[@]}" clean process-classes
find "$index_dir" -name '*.json.gz' -type f -printf '%f %s %T@\n' | sort >"$work/index-after-clean"
cmp -- "$work/index-before-clean" "$work/index-after-clean"
cp -- "$work/downloads/alternate.zip" "$archive"
run 0 changed-offline "${offline[@]}" process-classes
grep -Fq '0 validated hit(s)' "$work/changed-offline.log"
find "$index_dir" -name '*.json.gz' -type f -printf '%f\n' | sort >"$work/index-after-replacement"
test "$(wc -l <"$work/index-after-replacement")" -eq "$(( $(wc -l <"$work/index-before-clean") + 1 ))"
report="$work/build/dependency-elider-report.json"
trim_cache="$work/build/elided-artifacts/.trim-analysis-cache.json"
cp -- "$trim_cache" "$work/last-trim-cache.json"
find "$work/build/elided-artifacts" -name '*-trimmed.jar' -type f -exec sha256sum {} + \
  | sort >"$work/last-trimmed-jars"
test -s "$work/last-trimmed-jars"
cp -- "$report" "$work/last-successful-report.json"
printf '%s\n' 'invalid replacement' >"$archive"
run 1 corrupt-offline "${offline[@]}" process-classes
grep -Fq "Cannot inspect runtime $archive" "$work/corrupt-offline.log"
cmp -- "$work/last-successful-report.json" "$report"
cmp -- "$work/last-trim-cache.json" "$trim_cache"
find "$work/build/elided-artifacts" -name '*-trimmed.jar' -type f -exec sha256sum {} + \
  | sort >"$work/trimmed-jars-after-failure"
cmp -- "$work/last-trimmed-jars" "$work/trimmed-jars-after-failure"
run 0 replay "${offline[@]}" "$plugin:report"
grep -Fq "Runtime input $archive: Java" "$work/replay.log"

# The HTTPS proxy and trust store apply only to Maven subprocesses in this test.
"$java_home/bin/keytool" -importcert -alias elider-discovery-fixture -noprompt \
  -file "$work/discovery.pem" -keystore "$work/trust.p12" -storepass changeit >"$work/keytool.log" 2>&1
mkdir -p -- "$work/disco"
cat >"$work/disco/pom.xml" <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion><groupId>fixture</groupId><artifactId>runtime-discovery</artifactId><version>1</version>
  <build><plugins>
    <plugin><groupId>org.jreleaser</groupId><artifactId>jdks-maven-plugin</artifactId><version>1.26.0</version>
      <configuration><outputDirectory>${project.basedir}/prepared</outputDirectory><unpack>false</unpack>
        <pkgs><pkg><name>elider-target-jre</name><distribution>temurin</distribution>
          <version>${fixture.release}</version><platform>windows-x86_64</platform><packageType>jre</packageType>
          <archiveType>zip</archiveType><filename>runtime.zip</filename></pkg></pkgs>
      </configuration>
      <executions><execution><id>discover</id><phase>initialize</phase><goals><goal>setup-disco</goal></goals></execution></executions>
    </plugin>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-enforcer-plugin</artifactId><version>3.6.3</version>
      <executions><execution><id>archive-exists</id><phase>initialize</phase><goals><goal>enforce</goal></goals>
        <configuration><rules><requireFilesExist><files>
          <file>${project.basedir}/prepared/elider-target-jre/runtime.zip</file>
        </files></requireFilesExist></rules></configuration>
      </execution></executions>
    </plugin>
  </plugins></build>
</project>
XML
(
  maven="$repo_root/mvnw"
  export MAVEN_OPTS="${MAVEN_OPTS:-} -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=${address#*:}"
  export JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:-} \"-Djavax.net.ssl.trustStore=$work/trust.p12\" -Djavax.net.ssl.trustStorePassword=changeit"
  discovery=(-f "$work/disco/pom.xml")
  acquire 1 discovery-empty "${discovery[@]}" -Dfixture.release=21.0.999 initialize
  grep -Fq 'Disco returned no results' "$work/discovery-empty.log"
  grep -Fq 'Some required files are missing' "$work/discovery-empty.log"
  acquire 0 discovery-many "${discovery[@]}" -Dfixture.release=21.0.998 initialize
  grep -Fq 'Disco returned 2 package(s)' "$work/discovery-many.log"
  grep -Fq 'Checksum not available. Skipping verification' "$work/discovery-many.log"
  grep -Fq '/disco/v3.0/ids/first' "$work/server.log"
  cmp -- "$work/disco/prepared/$destination" "$work/downloads/runtime.zip"
  acquire 0 discovery-stale "${discovery[@]}" -Dfixture.release=21.0.999 initialize
  grep -Fq 'Disco returned no results' "$work/discovery-stale.log"
  grep -Fq 'RequireFilesExist passed' "$work/discovery-stale.log"
  cmp -- "$work/disco/prepared/$destination" "$work/downloads/runtime.zip"
)

mkdir -p -- "$work/reactor/child"
awk -v parent="$repo_root/examples/pom.xml" '
    /<relativePath>\.\.\/pom\.xml<\/relativePath>/ {
      print "        <relativePath>" parent "</relativePath>"; next
    }
    { print }
    /<artifactId>example-forbidden-code-app<\/artifactId>/ {
      print "    <packaging>pom</packaging><modules><module>child</module></modules>"
    }' "$pom" >"$work/reactor/pom.xml"
cat >"$work/reactor/child/pom.xml" <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>io.github.spockz</groupId><artifactId>example-forbidden-code-app</artifactId><version>0.1.0-SNAPSHOT</version></parent>
  <artifactId>runtime-profile-child</artifactId><packaging>pom</packaging>
</project>
XML
acquire 0 reactor -f "$work/reactor/pom.xml" "${prepare[@]}" "-Delider.runtime.cacheDirectory=$work/aggregate" initialize
test "$(grep -c 'setup-jdks (prepare-elider-runtime)' "$work/reactor.log")" = 1
test "$(grep -c 'enforce (check-elider-runtime-archive)' "$work/reactor.log")" = 1
cmp -- "$work/aggregate/$destination" "$work/downloads/runtime.zip"
printf 'Packaged runtime preparation, discovery, and offline handoff checks passed.\n'
