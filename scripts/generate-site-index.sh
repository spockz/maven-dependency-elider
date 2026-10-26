#!/usr/bin/env bash
# WHY: Transforms root README.md into site-ready index.md by adapting relative repository links for web publishing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/dependency-elider-maven-plugin/target/generated-site/markdown}"
OUTPUT_FILE="$OUTPUT_DIR/index.md"

mkdir -p "$OUTPUT_DIR"

# Adapt repository paths for the static documentation site:
# 1. Links to site markdown files (usage.md) -> usage.html
# 2. Links to repository-only docs -> GitHub main branch URLs
# 3. Relative link to LICENSE -> Apache 2.0 license URL
sed \
  -e 's|(\(dependency-elider-maven-plugin/src/site/markdown/\)\([^)]*\)\.md)|(\2.html)|g' \
  -e 's|(docs/adr/\([^)]*\)\.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/\1.md)|g' \
  -e 's|(docs/research/\([^)]*\)\.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/docs/research/\1.md)|g' \
  -e 's|(docs/handovers/\([^)]*\)\.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/docs/handovers/\1.md)|g' \
  -e 's|(docs/faq\.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/docs/faq.md)|g' \
  -e 's|(docs/contributor-decisions-and-faq\.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md)|g' \
  -e 's|(docs/adr/)|(https://github.com/spockz/maven-dependency-elider/tree/main/docs/adr/)|g' \
  -e 's|(docs/research/)|(https://github.com/spockz/maven-dependency-elider/tree/main/docs/research/)|g' \
  -e 's|(docs/handovers/)|(https://github.com/spockz/maven-dependency-elider/tree/main/docs/handovers/)|g' \
  -e 's|(CONTRIBUTING.md)|(https://github.com/spockz/maven-dependency-elider/blob/main/CONTRIBUTING.md)|g' \
  -e 's|(LICENSE)|(https://www.apache.org/licenses/LICENSE-2.0.txt)|g' \
  "$REPO_ROOT/README.md" > "$OUTPUT_FILE"

echo "Generated site index at $OUTPUT_FILE from README.md"
