// WHY: Validates claim-to-output provenance stored under a verified report proof.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.optionalText;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireArray;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireObject;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireText;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Validates source claims and the exact classes attributed to each claim. */
final class MavenElisionReportClaimPayloadValidator {
  /** Shared JSON field name for a claim kind. */
  private static final String TYPE = "type";

  /** Shared JSON field name for a claim value. */
  private static final String CLAIM = "claim";

  /** Shared JSON field name for the archive binary entry path. */
  private static final String PATH = "path";

  /** Shared JSON field name for the emitted class digest. */
  private static final String SHA256 = "sha256";

  /** Exact fields accepted for a claim attribution. */
  private static final Set<String> CLAIM_FIELDS =
      Set.of(TYPE, CLAIM, "sourceEntry", "routineOwnerBinaryName", "emittedClasses");

  /** Exact fields accepted for one emitted class. */
  private static final Set<String> CLASS_FIELDS = Set.of(PATH, SHA256);

  private MavenElisionReportClaimPayloadValidator() {}

  /* default */ static void validate(final JsonNode node) throws IOException {
    requireObject(node, CLAIM_FIELDS, "claim attribution");
    requireText(node.get(TYPE), TYPE, "FILE|ROUTINE");
    requireText(node.get(CLAIM), CLAIM, ".+");
    requireText(node.get("sourceEntry"), "sourceEntry", ".+");
    optionalText(node.get("routineOwnerBinaryName"), "routineOwnerBinaryName");
    final JsonNode classes = node.get("emittedClasses");
    requireArray(classes, "emittedClasses");
    if (classes.isEmpty()) {
      throw new IOException("Elision report emittedClasses must not be empty");
    }
    for (final JsonNode classEntry : classes) {
      requireObject(classEntry, CLASS_FIELDS, "emitted class");
      requireText(classEntry.get(PATH), PATH, ".+");
      requireText(classEntry.get(SHA256), SHA256, "[0-9a-f]{64}");
    }
  }
}
