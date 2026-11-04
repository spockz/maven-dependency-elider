/* WHY: Lets users knowingly accept duplicate classes across JARs instead of hard-failing, with one
 * explicit action per matching class. */

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/** Selects the owner action for exact class names or glob patterns. */
final class DuplicateClassPolicy {
  /** Policy that tolerates no duplicates. */
  /* package */ static final DuplicateClassPolicy NONE =
      new DuplicateClassPolicy(List.of(), List.of());

  /** Glob wildcard whose repetition selects package-spanning matching. */
  private static final char STAR = '*';

  /** Normalized patterns for whole-JAR retention. */
  private final List<String> retainOwnerGlobs;

  /** Normalized patterns for owners eligible for sibling trimming. */
  private final List<String> trimOwnerGlobs;

  /** Compiled once for matching against the complete inventory. */
  private final List<Pattern> retainPatterns;

  /** Compiled sibling-trimming patterns. */
  private final List<Pattern> trimPatterns;

  /** What happens to the JARs that own a tolerated duplicate class. */
  /* package */ enum Action {
    /** Every owning JAR is kept whole and untrimmed. */
    RETAIN_JARS,
    /** The duplicate class is kept in every owner while other classes may be trimmed. */
    TRIM_OTHER_CLASSES
  }

  /** Validates, normalizes, and compiles the configured patterns. */
  /* package */ DuplicateClassPolicy(
      final List<String> retainOwners, final List<String> trimOwners) {
    retainOwnerGlobs = normalize(retainOwners);
    trimOwnerGlobs = normalize(trimOwners);
    for (final String pattern : retainOwnerGlobs) {
      if (trimOwnerGlobs.contains(pattern)) {
        throw new IllegalArgumentException(
            "Duplicate class pattern is listed for both retain and trim: " + pattern);
      }
    }
    retainPatterns = retainOwnerGlobs.stream().map(DuplicateClassPolicy::glob).toList();
    trimPatterns = trimOwnerGlobs.stream().map(DuplicateClassPolicy::glob).toList();
  }

  /* package */ List<String> retainOwners() {
    return retainOwnerGlobs;
  }

  /* package */ List<String> trimOwners() {
    return trimOwnerGlobs;
  }

  /* package */ boolean isEmpty() {
    return retainOwnerGlobs.isEmpty() && trimOwnerGlobs.isEmpty();
  }

  /** Returns the action for a dotted or slashed class name, if any pattern matches. */
  /* package */ Optional<Action> actionFor(final String className) {
    final String dotted = className.replace('/', '.');
    if (matchesAny(retainPatterns, dotted)) {
      return Optional.of(Action.RETAIN_JARS);
    }
    return matchesAny(trimPatterns, dotted)
        ? Optional.of(Action.TRIM_OTHER_CLASSES)
        : Optional.empty();
  }

  /** Returns whether any pattern tolerates duplicates of the class. */
  /* package */ boolean tolerates(final String className) {
    return actionFor(className).isPresent();
  }

  private static boolean matchesAny(final List<Pattern> patterns, final String dotted) {
    for (final Pattern pattern : patterns) {
      if (pattern.matcher(dotted).matches()) {
        return true;
      }
    }
    return false;
  }

  private static Pattern glob(final String pattern) {
    final StringBuilder regex = new StringBuilder();
    int index = 0;
    while (index < pattern.length()) {
      final char current = pattern.charAt(index);
      if (current == STAR && index + 1 < pattern.length() && pattern.charAt(index + 1) == STAR) {
        regex.append(".*");
        index += 2;
      } else if (current == STAR) {
        regex.append("[^.]*");
        index++;
      } else {
        regex.append(Pattern.quote(String.valueOf(current)));
        index++;
      }
    }
    return Pattern.compile(regex.toString());
  }

  private static List<String> normalize(final List<String> patterns) {
    if (patterns == null) {
      return List.of();
    }
    return patterns.stream()
        .map(
            pattern -> {
              if (pattern == null || pattern.isBlank()) {
                throw new IllegalArgumentException("Duplicate class pattern must not be blank");
              }
              return pattern.trim().replace('/', '.');
            })
        .toList();
  }
}
