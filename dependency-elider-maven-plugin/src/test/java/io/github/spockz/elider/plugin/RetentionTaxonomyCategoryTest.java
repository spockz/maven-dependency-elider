// WHY: Unit tests verifying RetentionTaxonomyCategory parsing, serial names, and invalid value rejection.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

final class RetentionTaxonomyCategoryTest {

  @Test
  @DisplayName("serialName matches the exact schema-1 taxonomy token")
  void serialNameMatchesExpectedTokens() {
    assertAll(
        () -> assertThat(RetentionTaxonomyCategory.CONSERVATIVE_METADATA.serialName())
            .isEqualTo("conservative_metadata"),
        () -> assertThat(RetentionTaxonomyCategory.GENERATED_AOT_REGISTRATION.serialName())
            .isEqualTo("generated_aot_registration"),
        () -> assertThat(RetentionTaxonomyCategory.NOT_OBSERVED_IN_WORKLOAD.serialName())
            .isEqualTo("not_observed_in_workload"),
        () -> assertThat(RetentionTaxonomyCategory.BYTECODE_LINK_CLOSURE.serialName())
            .isEqualTo("bytecode_link_closure"));
  }

  @Test
  @DisplayName("parse returns correct category case-insensitively and handles whitespace")
  void parseValidValues() {
    assertAll(
        () -> assertThat(RetentionTaxonomyCategory.parse("conservative_metadata"))
            .isEqualTo(RetentionTaxonomyCategory.CONSERVATIVE_METADATA),
        () -> assertThat(RetentionTaxonomyCategory.parse(" GENERATED_AOT_REGISTRATION "))
            .isEqualTo(RetentionTaxonomyCategory.GENERATED_AOT_REGISTRATION),
        () -> assertThat(RetentionTaxonomyCategory.parse("not_observed_in_workload"))
            .isEqualTo(RetentionTaxonomyCategory.NOT_OBSERVED_IN_WORKLOAD),
        () -> assertThat(RetentionTaxonomyCategory.parse("bytecode_link_closure"))
            .isEqualTo(RetentionTaxonomyCategory.BYTECODE_LINK_CLOSURE));
  }

  @Test
  @DisplayName("parse throws IllegalArgumentException for unknown or null values")
  void parseInvalidValues() {
    assertAll(
        () -> assertThatThrownBy(() -> RetentionTaxonomyCategory.parse("unknown"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown retention taxonomy category"),
        () -> assertThatThrownBy(() -> RetentionTaxonomyCategory.parse(null))
            .isInstanceOf(NullPointerException.class));
  }
}
