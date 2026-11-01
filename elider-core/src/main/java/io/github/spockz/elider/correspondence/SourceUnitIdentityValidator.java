// WHY: Binds basename-only class SourceFile metadata to one package path. Duplicate identities
// would otherwise let a CNA path claim point to a different source unit with the same basename.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates unique source package paths and basenames. */
final class SourceUnitIdentityValidator {
  /** A source unit must declare one package and one path identity. */
  private static final int UNIQUE_PACKAGE_COUNT = 1;

  private SourceUnitIdentityValidator() {}

  @SuppressWarnings("PMD.UseConcurrentHashMap") // This lookup map is local to one reproduction.
  /* default */ static void requireUnique(final List<SourceReproductionResult.SourceUnit> units)
      throws IOException {
    final Map<String, String> entriesByIdentity = new HashMap<>();
    for (final SourceReproductionResult.SourceUnit unit : units) {
      final String packageName = sourcePackage(unit);
      final String basename = basename(unit.sourceEntry());
      final String canonicalPath = packagePath(packageName, basename);
      if (!hasCanonicalSuffix(unit.sourceEntry(), canonicalPath)) {
        throw new IOException("Source archive path disagrees with the declared Java package");
      }
      if (entriesByIdentity.putIfAbsent(packageName + "/" + basename, unit.sourceEntry()) != null) {
        throw new IOException("Source archive has ambiguous package and basename identities");
      }
    }
  }

  private static String sourcePackage(final SourceReproductionResult.SourceUnit unit)
      throws IOException {
    if (unit.topLevelTypes().isEmpty()) {
      throw new IOException("Source unit has no supported top-level Java declaration");
    }
    final Set<String> packages = new HashSet<>();
    unit.topLevelTypes().forEach(type -> packages.add(packageName(type)));
    if (packages.size() != UNIQUE_PACKAGE_COUNT) {
      throw new IOException("Source unit declares conflicting Java packages");
    }
    return packages.iterator().next();
  }

  private static String packageName(final String binaryName) {
    final int separator = binaryName.lastIndexOf('.');
    return separator < 0 ? "" : binaryName.substring(0, separator);
  }

  private static String basename(final String sourceEntry) {
    return sourceEntry.substring(sourceEntry.lastIndexOf('/') + 1);
  }

  private static String packagePath(final String packageName, final String basename) {
    return packageName.isEmpty() ? basename : packageName.replace('.', '/') + "/" + basename;
  }

  private static boolean hasCanonicalSuffix(final String entry, final String suffix) {
    return entry.equals(suffix) || entry.endsWith("/" + suffix);
  }
}
