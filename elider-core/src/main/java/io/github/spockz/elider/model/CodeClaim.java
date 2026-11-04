/* WHY: Separates declarations from untrusted leads. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** A locator classified by the assertion's semantics. */
public record CodeClaim(Kind kind, CodeReference reference) implements Comparable<CodeClaim> {
  /** Whether the locator is an explicit declaration or a heuristic lead. */
  public enum Kind {
    DECLARED,
    HEURISTIC
  }

  /** Validates the claim. */
  public CodeClaim {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(reference, "reference");
  }

  /** Creates an explicit declaration. */
  public static CodeClaim declared(final CodeReference reference) {
    return new CodeClaim(Kind.DECLARED, reference);
  }

  /** Creates a lead that cannot itself grant proof eligibility. */
  public static CodeClaim heuristic(final CodeReference reference) {
    return new CodeClaim(Kind.HEURISTIC, reference);
  }

  /** Combines equivalent claims while retaining their original locator spellings. */
  public CodeClaim merge(final CodeClaim other) {
    if (kind != other.kind || !reference.equals(other.reference)) {
      throw new IllegalArgumentException("only equivalent code claims can be combined");
    }
    return new CodeClaim(kind, reference.withOriginalValues(other.reference.originalValues()));
  }

  @Override
  public int compareTo(final CodeClaim other) {
    final int kindOrder = kind.compareTo(other.kind);
    if (kindOrder != 0) {
      return kindOrder;
    }
    return reference.compareTo(other.reference);
  }
}
