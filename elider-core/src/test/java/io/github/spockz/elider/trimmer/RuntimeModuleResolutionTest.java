/* WHY: Verifies transitive requirements and service binding against a linked runtime image. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.module.ModuleDescriptor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.spi.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class RuntimeModuleResolutionTest {
  private static final String CONTRACT = "fixture.contract";
  private static final String BRIDGE = "fixture.bridge";
  private static final String PROVIDER = "fixture.provider";
  private static final String APP = "fixture.application";
  private static final String SERVICE = "fixture.api.RuntimeService";
  private static final String DESCRIPTOR = "module-info.java";

  @Test
  void followsTransitiveRequirementsAndBindsOnlyApplicableProviders(@TempDir final Path directory)
      throws IOException {
    final Optional<ToolProvider> javac = ToolProvider.findFirst("javac");
    final Optional<ToolProvider> jlink = ToolProvider.findFirst("jlink");
    assumeTrue(javac.isPresent() && jlink.isPresent(), "The fixture needs the JDK image tools");
    final Path sources = directory.resolve("sources");
    source(sources, CONTRACT, DESCRIPTOR, "module fixture.contract { exports fixture.api; }");
    source(
        sources,
        CONTRACT,
        "fixture/api/RuntimeService.java",
        "package fixture.api; public interface RuntimeService {}");
    source(
        sources,
        BRIDGE,
        DESCRIPTOR,
        "module fixture.bridge { requires transitive fixture.contract; }");
    source(
        sources,
        PROVIDER,
        DESCRIPTOR,
        """
        module fixture.provider {
          requires fixture.contract;
          provides fixture.api.RuntimeService with fixture.impl.Provider;
        }
        """);
    source(
        sources,
        PROVIDER,
        "fixture/impl/Provider.java",
        "package fixture.impl; public class Provider implements fixture.api.RuntimeService {}");
    final Path modules = directory.resolve("modules");
    final Path image = directory.resolve("image");
    run(
        javac.orElseThrow(),
        "-d",
        modules.toString(),
        "--module-source-path",
        sources.toString(),
        "--module",
        CONTRACT + "," + BRIDGE + "," + PROVIDER);
    run(
        jlink.orElseThrow(),
        "--module-path",
        modules.toString(),
        "--add-modules",
        BRIDGE + "," + PROVIDER,
        "--strip-debug",
        "--output",
        image.toString());
    final JdkPlatformContext.PlatformSnapshot snapshot = JdkPlatformContext.inspectRuntime(image);
    final JdkPlatformContext.PlatformSnapshot withoutService =
        snapshot.forApplicationModule(ModuleDescriptor.newModule(APP).requires(BRIDGE).build());
    final JdkPlatformContext.PlatformSnapshot withService =
        snapshot.forApplicationModule(
            ModuleDescriptor.newModule(APP).requires(BRIDGE).uses(SERVICE).build());
    assertAll(
        () ->
            assertThat(withoutService.moduleDescriptors())
                .extracting(ModuleDescriptor::name)
                .containsExactlyInAnyOrder("java.base", BRIDGE, CONTRACT),
        () ->
            assertThat(withService.moduleDescriptors())
                .extracting(ModuleDescriptor::name)
                .containsExactlyInAnyOrder("java.base", BRIDGE, CONTRACT, PROVIDER),
        () ->
            assertThat(
                    new JdkApiClassTableReader()
                        .readFrozen(withService)
                        .getClass("fixture/impl/Provider"))
                .isNotNull());
  }

  private static void source(
      final Path directory, final String module, final String name, final String content)
      throws IOException {
    final Path path = directory.resolve(module).resolve(name);
    Files.createDirectories(path.getParent());
    Files.writeString(path, content);
  }

  private static void run(final ToolProvider tool, final String... arguments) {
    final StringWriter log = new StringWriter();
    final PrintWriter output = new PrintWriter(log);
    final int status = tool.run(output, output, arguments);
    assertThat(status).as(log.toString()).isZero();
  }
}
