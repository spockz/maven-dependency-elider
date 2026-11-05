#!/usr/bin/env bash
# WHY: Verifies the check workflow fixes supported Go and Markdown formatting before linting.
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
formatter="${MARKDOWNLINT:-$repository_root/.scratch/tools/node_modules/.bin/markdownlint-cli2}"
formatter="$(cd -- "$(dirname -- "$formatter")" && pwd)/$(basename -- "$formatter")"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

cp -- "$repository_root/Makefile" "$repository_root/pom.xml" \
  "$repository_root/.markdownlint-cli2.yaml" "$work_dir/"
mkdir -p -- "$work_dir/scripts" "$work_dir/docs" "$work_dir/dependency-elider-maven-plugin/src/site"
printf 'package fixture\n\nfunc value( ) int {return 1}\n' > "$work_dir/scripts/fixture.go"
printf '# Fixture\n\n\nText.\n' > "$work_dir/docs/fixture.md"

make -C "$work_dir" fmt MAVEN=true MARKDOWNLINT="$formatter" >/dev/null
if [[ -n "$(gofmt -l "$work_dir/scripts/fixture.go")" ]]; then
  printf '%s\n' 'make fmt did not format Go sources' >&2
  exit 1
fi
"$formatter" "$work_dir/docs/fixture.md" >/dev/null

mkdir -p -- "$work_dir/java/src/main/java" "$work_dir/before" "$work_dir/after"
cat > "$work_dir/java/pom.xml" <<'POM'
<!-- WHY: Inherits the repository's actual Java formatter for this isolated test. -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>io.github.spockz</groupId>
    <artifactId>maven-dependency-elider</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <relativePath>../pom.xml</relativePath>
  </parent>
  <artifactId>format-regression</artifactId>
  <build><plugins><plugin>
    <groupId>com.diffplug.spotless</groupId>
    <artifactId>spotless-maven-plugin</artifactId>
  </plugin></plugins></build>
</project>
POM
cat > "$work_dir/java/src/main/java/FormatProbe.java" <<'JAVA'
// WHY: Verifies formatting preserves the value of a long Java string.
public class FormatProbe {
  public static final String VALUE = "This is a deliberately long Java string containing several separate words so that automatic formatting can wrap it safely without changing the program value.";
}
JAVA
javac -d "$work_dir/before" "$work_dir/java/src/main/java/FormatProbe.java"
javap -constants -classpath "$work_dir/before" FormatProbe > "$work_dir/before.txt"
"$repository_root/mvnw" --batch-mode --no-transfer-progress \
  -f "$work_dir/java/pom.xml" spotless:apply > /dev/null
awk 'length($0) > 100 {print "Java formatter left a long line at " NR > "/dev/stderr"; failed = 1} END {exit failed}' \
  "$work_dir/java/src/main/java/FormatProbe.java"
javac -d "$work_dir/after" "$work_dir/java/src/main/java/FormatProbe.java"
javap -constants -classpath "$work_dir/after" FormatProbe > "$work_dir/after.txt"
cmp -- "$work_dir/before.txt" "$work_dir/after.txt"
cp -- "$work_dir/java/src/main/java/FormatProbe.java" "$work_dir/first-pass.java"
"$repository_root/mvnw" --batch-mode --no-transfer-progress \
  -f "$work_dir/java/pom.xml" spotless:apply > /dev/null
cmp -- "$work_dir/java/src/main/java/FormatProbe.java" "$work_dir/first-pass.java"
