// WHY: Executes the generated Maven help goal so coverage includes its user-visible behavior.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.dependency_elider_maven_plugin.HelpMojo;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.junit.jupiter.api.Test;

/** Exercises Maven-generated help output. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor", // JUnit owns test-instance creation.
  "PMD.UnitTestContainsTooManyAsserts" // Assertions verify distinct help-output contracts.
})
final class HelpMojoCoverageTest {
  @Test
  void rendersDetailedHelpForEveryGoal()
      throws MojoExecutionException, ReflectiveOperationException {
    final HelpOutput output = runHelp(true, null, 45, 2);

    assertAll(
        "detailed help output",
        () ->
            assertThat(output.info())
                .singleElement()
                .satisfies(
                    help ->
                        assertThat(help)
                            .contains(
                                "This plugin has 5 goals",
                                "dependency-elider:analyze",
                                "dependency-elider:elide",
                                "dependency-elider:help",
                                "dependency-elider:report",
                                "dependency-elider:update-cve-index",
                                "Available parameters:",
                                "lineLength")),
        () ->
            assertThat(
                    output.info().stream()
                        .anyMatch(
                            help ->
                                help.contains(
                                    "Retains unproven ServiceLoader dynamic\n"
                                        + "      roots declared in META-INF/services/.")))
                .as("long parameter descriptions wrap at the configured line length")
                .isTrue());
  }

  @Test
  void filtersToRequestedGoalAndDefaultsNonPositiveLayoutOptions()
      throws MojoExecutionException, ReflectiveOperationException {
    final HelpOutput output = runHelp(false, "report", 0, -1);
    final String help = String.join("\n", output.info());

    assertThat(help)
        .contains("dependency-elider:report")
        .doesNotContain("dependency-elider:analyze", "This plugin has 5 goals");
    assertThat(output.warnings())
        .contains(
            "The parameter 'lineLength' should be positive, using '80' as default.",
            "The parameter 'indentSize' should be positive, using '2' as default.");
  }

  private static HelpOutput runHelp(
      final boolean detail, final String goal, final int lineLength, final int indentSize)
      throws MojoExecutionException, ReflectiveOperationException {
    final List<String> info = new ArrayList<>();
    final List<String> warnings = new ArrayList<>();
    final HelpMojo mojo = new HelpMojo();
    set(mojo, "detail", detail);
    set(mojo, "goal", goal);
    set(mojo, "lineLength", lineLength);
    set(mojo, "indentSize", indentSize);
    mojo.setLog(recordingLog(info, warnings));
    mojo.execute();
    return new HelpOutput(info, warnings);
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static Log recordingLog(final List<String> info, final List<String> warnings) {
    return (Log)
        Proxy.newProxyInstance(
            Log.class.getClassLoader(),
            new Class<?>[] {Log.class},
            (proxy, method, arguments) -> {
              if (arguments != null
                  && arguments.length > 0
                  && arguments[0] instanceof CharSequence message) {
                switch (method.getName()) {
                  case "info" -> info.add(message.toString());
                  case "warn" -> warnings.add(message.toString());
                  default -> {}
                }
              }
              return method.getReturnType() == boolean.class ? Boolean.TRUE : null;
            });
  }

  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  private static void set(final Object target, final String fieldName, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private record HelpOutput(List<String> info, List<String> warnings) {}
}
