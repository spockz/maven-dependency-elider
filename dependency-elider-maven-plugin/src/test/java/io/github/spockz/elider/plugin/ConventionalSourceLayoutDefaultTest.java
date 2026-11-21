/* WHY: Verifies the user-visible Maven descriptor defaults for source attribution. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.apache.maven.plugin.descriptor.Parameter;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugin.descriptor.PluginDescriptorBuilder;
import org.codehaus.plexus.configuration.PlexusConfigurationException;
import org.junit.jupiter.api.Test;

/** Checks the Maven goal configuration users receive from the generated descriptor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class ConventionalSourceLayoutDefaultTest {
  /** Descriptor parameter shared by the elide and analyze goals. */
  private static final String SOURCE_LAYOUT_PARAMETER = "assumeConventionalJavaSourceLayout";

  @Test
  void elideAndAnalyzeDefaultToConventionalSourceLayoutAssumption()
      throws IOException, PlexusConfigurationException {
    final PluginDescriptor descriptor = readDescriptor();

    assertAll(
        "both source-attribution goals default to the conventional Java layout",
        () ->
            assertThat(parameter(descriptor, "elide", SOURCE_LAYOUT_PARAMETER).getDefaultValue())
                .as("elide goal parameter default")
                .isEqualTo("true"),
        () ->
            assertThat(parameter(descriptor, "analyze", SOURCE_LAYOUT_PARAMETER).getDefaultValue())
                .as("analyze goal parameter default")
                .isEqualTo("true"));
  }

  @Test
  void bothGoalsBindTheDefaultOffForbiddenCodeProperty()
      throws IOException, PlexusConfigurationException {
    final PluginDescriptor descriptor = readDescriptor();
    for (final String goal : java.util.List.of("analyze", "elide")) {
      final Parameter setting = parameter(descriptor, goal, "failOnForbiddenCode");
      assertAll(
          goal,
          () -> assertThat(setting.getDefaultValue()).isEqualTo("false"),
          () -> assertThat(setting.getExpression()).isEqualTo("${elide.failOnForbiddenCode}"));
    }
  }

  private static PluginDescriptor readDescriptor()
      throws IOException, PlexusConfigurationException {
    try (InputStream input =
            Objects.requireNonNull(
                ConventionalSourceLayoutDefaultTest.class.getResourceAsStream(
                    "/META-INF/maven/plugin.xml"),
                "Generated Maven plugin descriptor is missing");
        InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
      return new PluginDescriptorBuilder().build(reader);
    }
  }

  private static Parameter parameter(
      final PluginDescriptor descriptor, final String goal, final String name) {
    return descriptor.getMojos().stream()
        .filter(mojo -> goal.equals(mojo.getGoal()))
        .map(mojo -> mojo.getParameterMap().get(name))
        .filter(Objects::nonNull)
        .findFirst()
        .orElseThrow(() -> new AssertionError("Missing parameter " + name + " on goal " + goal));
  }
}
