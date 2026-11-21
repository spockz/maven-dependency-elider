// WHY: Validates explicit policy symbols before physical inventory assessment.

package io.github.spockz.elider.advisory;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/** A validated explicit class or method policy target. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CyclomaticComplexity"})
public record ForbiddenSymbol(String value, String owner, String method, List<String> parameters) {
  private static final String IDENT =
      "[\\p{javaJavaIdentifierStart}][\\p{javaJavaIdentifierPart}]*";
  private static final Pattern QUALIFIED = Pattern.compile(IDENT + "(?:\\." + IDENT + ")+");
  private static final Pattern NAME = Pattern.compile(IDENT);
  private static final Pattern TYPE =
      Pattern.compile(
          "(?:boolean|byte|short|char|int|long|float|double|"
              + IDENT
              + "(?:\\."
              + IDENT
              + ")+)(?:\\[\\])*");

  /** Preserve immutable parameters. */
  public ForbiddenSymbol {
    parameters = List.copyOf(parameters);
  }

  /** Returns whether the spelling also selects a constructor. */
  public boolean usesConstructorName() {
    return method != null && method.equals(owner.substring(owner.lastIndexOf('.') + 1));
  }

  /** Parse an exact symbol or explicit class wildcard. */
  public static ForbiddenSymbol parse(final String value) {
    if (value == null || !value.equals(value.trim())) {
      throw new IllegalArgumentException("Invalid forbidden symbol: " + value);
    }
    final int hash = value.indexOf('#');
    final String owner = hash < 0 ? value : value.substring(0, hash);
    final String base = owner.replaceFirst("(?:\\.\\*\\*?|\\$\\*\\*?)$", "");
    final boolean wildcard = !base.equals(owner);
    final boolean packageWildcard = wildcard && owner.charAt(base.length()) == '.';
    if (!(QUALIFIED.matcher(base).matches() || (packageWildcard && NAME.matcher(base).matches()))
        || (wildcard && hash >= 0)) {
      throw new IllegalArgumentException("Invalid forbidden owner: " + value);
    }
    if (hash < 0) {
      return new ForbiddenSymbol(value, owner, null, List.of());
    }
    final int open = value.indexOf('(', hash);
    if (open < 0
        || !value.endsWith(")")
        || !NAME.matcher(value.substring(hash + 1, open)).matches()) {
      throw new IllegalArgumentException("Invalid forbidden method: " + value);
    }
    final String arguments = value.substring(open + 1, value.length() - 1);
    final List<String> parameters =
        arguments.isEmpty()
            ? List.of()
            : Arrays.stream(arguments.split(",", -1)).map(String::trim).toList();
    if (parameters.stream().anyMatch(p -> !TYPE.matcher(p).matches())) {
      throw new IllegalArgumentException("Invalid forbidden parameters: " + value);
    }
    return new ForbiddenSymbol(value, owner, value.substring(hash + 1, open), parameters);
  }
}
