/* WHY: Distinguishes omitted and explicitly empty fields. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** A field value that distinguishes absence from explicit emptiness. */
public record FieldValue<T>(boolean supplied, T value) {
  /** Validates that supplied values are present and omitted values carry no payload. */
  public FieldValue {
    if (supplied) {
      Objects.requireNonNull(value, "supplied value");
    } else if (value != null) {
      throw new IllegalArgumentException("omitted values must not carry a payload");
    }
  }

  /** Creates a supplied field, including an explicitly empty value. */
  public static <T> FieldValue<T> supplied(final T value) {
    return new FieldValue<>(true, value);
  }

  /** Creates an omitted field. */
  public static <T> FieldValue<T> omitted() {
    return new FieldValue<>(false, null);
  }
}
