#!/usr/bin/env bash
# WHY: Verifies link translation when the repository FAQ is published on the Maven site.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
generated=$(mktemp -d)
trap 'rm -rf -- "$generated"' EXIT

bash "$repo_root/scripts/generate-site-index.sh" "$generated" >/dev/null
grep -Fq '](usage.html#forbidden-code-policy)' "$generated/faq.md"
grep -Fq '](https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md)' "$generated/faq.md"
grep -Fq '](https://github.com/spockz/maven-dependency-elider/blob/main/dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java)' "$generated/faq.md"
