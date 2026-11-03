// WHY: Categorizes retained dependencies into the 4-category taxonomy required by WP-PLATFORM-01.

package io.github.spockz.elider.plugin;

import java.util.Objects;

/**
 * The 4 retention provenance categories defined by WP-PLATFORM-01: - conservative_metadata:
 * Retained solely because of discovery metadata (Spring imports/conditions/properties). -
 * generated_aot_registration: Retained by explicit Spring AOT generated bean definitions, proxies,
 * or runtime hints. - not_observed_in_workload: Unobserved during recorded workloads
 * (trace/class-list/probes). - bytecode_link_closure: Retained due to hard bytecode references
 * (application code or transitive bytecode links).
 */
public enum RetentionTaxonomyCategory {
  CONSERVATIVE_METADATA("conservative_metadata"),
  GENERATED_AOT_REGISTRATION("generated_aot_registration"),
  NOT_OBSERVED_IN_WORKLOAD("not_observed_in_workload"),
  BYTECODE_LINK_CLOSURE("bytecode_link_closure");

  private final String serialName;

  RetentionTaxonomyCategory(final String serialName) {
    this.serialName = serialName;
  }

  /** Returns the serialized string representation of the taxonomy category. */
  public String serialName() {
    return serialName;
  }

  /**
   * Parses a serialized string representation into a category enum constant.
   *
   * @param value serialized string
   * @return matching taxonomy category
   */
  public static RetentionTaxonomyCategory parse(final String value) {
    Objects.requireNonNull(value, "value");
    for (final RetentionTaxonomyCategory cat : values()) {
      if (cat.serialName.equalsIgnoreCase(value.trim())) {
        return cat;
      }
    }
    throw new IllegalArgumentException("Unknown retention taxonomy category: " + value);
  }
}
