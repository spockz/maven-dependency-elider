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
  private static final String PARAMETER = "assumeConventionalJavaSourceLayout";

  @Test
  void elideAndAnalyzeDefaultToConventionalSourceLayoutAssumption()
      throws IOException, PlexusConfigurationException {
    final PluginDescriptor descriptor = readDescriptor();

    assertAll(
        "both source-attribution goals default to the conventional Java layout",
        () ->
            assertThat(parameterDefault(descriptor, "elide"))
                .as("elide goal parameter default")
                .isEqualTo("true"),
        () ->
            assertThat(parameterDefault(descriptor, "analyze"))
                .as("analyze goal parameter default")
                .isEqualTo("true"));
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

  private static String parameterDefault(final PluginDescriptor descriptor, final String goal) {
    return descriptor.getMojos().stream()
        .filter(mojo -> goal.equals(mojo.getGoal()))
        .map(mojo -> mojo.getParameterMap().get(PARAMETER))
        .filter(Objects::nonNull)
        .map(Parameter::getDefaultValue)
        .filter(Objects::nonNull)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("Missing default for " + PARAMETER + " on goal " + goal));
  }
}
