/* WHY: Verifies that explicit runtime inputs stay ordered, project-relative, and diagnosable. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class MavenRuntimePlatformsTest {
  @Test
  void retainsTheInspectedImageAndTheMissingModuleDiagnostic(@TempDir final Path output)
      throws IOException {
    final ClassWriter classWriter = new ClassWriter(0);
    classWriter.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final ModuleVisitor module = classWriter.visitModule("explicit.application", 0, null);
    module.visitRequire("java.base", Opcodes.ACC_MANDATED, null);
    module.visitRequire("fixture.missing", 0, null);
    module.visitEnd();
    classWriter.visitEnd();
    Files.write(output.resolve("module-info.class"), classWriter.toByteArray());
    final MavenRuntimePlatforms selection =
        MavenRuntimePlatforms.inspect(output, List.of(System.getProperty("java.home")), null)
            .forProductionOutput(output.toFile());
    final MavenRuntimeCoverage coverage =
        MavenRuntimeCoverage.from(selection, Runtime.version().feature(), true, List.of());
    assertAll(
        () -> assertThatThrownBy(selection::requireLinkage).hasMessageContaining("fixture.missing"),
        () -> assertThat(coverage.analyzedReleases()).isEmpty(),
        () ->
            assertThat(coverage.inputs())
                .singleElement()
                .satisfies(
                    input ->
                        assertAll(
                            () ->
                                assertThat(input.version()).isEqualTo(Runtime.version().toString()),
                            () -> assertThat(input.problem()).isNull(),
                            () -> assertThat(input.linkageProblem()).contains("fixture.missing"))));
  }

  @Test
  void savesCoverageWarningSeparatelyFromAnUnavailableInput(@TempDir final Path base) {
    final MavenRuntimePlatforms platforms =
        MavenRuntimePlatforms.inspect(base, List.of("unavailable.zip"), null);
    final MavenRuntimeCoverage coverage = MavenRuntimeCoverage.from(platforms, 21, true, List.of());
    assertAll(
        () ->
            assertThat(coverage.compilerTargetWarning())
                .contains("Java 21", "no runtime inspected"),
        () -> assertThat(coverage.analyzedReleases()).isEmpty(),
        () ->
            assertThat(coverage.inputs())
                .singleElement()
                .satisfies(
                    input ->
                        assertAll(
                            () ->
                                assertThat(input.path())
                                    .isEqualTo(base.resolve("unavailable.zip").toString()),
                            () -> assertThat(input.version()).isNull(),
                            () -> assertThat(input.problem()).contains("does not exist"))));
  }

  @Test
  void retainsUnavailableInputsWithoutSelectingTheRunningRuntime(@TempDir final Path base) {
    final Path absolute = base.resolve("second.zip");
    final MavenRuntimePlatforms selection =
        MavenRuntimePlatforms.inspect(
            base, List.of("images/first.tar.gz", absolute.toString()), null);
    assertAll(
        () ->
            assertThat(selection.inputs())
                .extracting(MavenRuntimePlatforms.Input::path)
                .containsExactly(base.resolve("images/first.tar.gz"), absolute),
        () ->
            assertThat(selection.inputs())
                .allSatisfy(
                    input -> {
                      assertThat(input.platform()).isNull();
                      assertThat(input.problem()).contains(input.path().toString());
                    }),
        () -> assertThat(MavenRuntimePlatforms.inspect(base, List.of(), null).inputs()).isEmpty(),
        () ->
            assertThatThrownBy(() -> MavenRuntimePlatforms.inspect(base, List.of("  "), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("blank"),
        () ->
            assertThat(
                    MavenRuntimeCoverage.from(selection, 21, true, List.of())
                        .compilerTargetWarning())
                .contains("Java 21", "no runtime inspected"));
  }
}
