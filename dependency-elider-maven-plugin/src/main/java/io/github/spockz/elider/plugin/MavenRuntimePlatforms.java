/* WHY: Shares platform evidence while preserving input paths and inspection failures. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import io.github.spockz.elider.trimmer.JdkPlatformContext.PlatformSnapshot;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.module.ModuleDescriptor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;

@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record MavenRuntimePlatforms(List<Input> inputs) {
  record Input(Path path, PlatformSnapshot platform, String problem, String linkageProblem) {
    Input(final Path path, final PlatformSnapshot platform, final String problem) {
      this(path, platform, problem, null);
    }

    private Input resolveModules(final ModuleDescriptor descriptor) {
      final PlatformSnapshot snapshot = platform();
      if (snapshot == null) {
        return this;
      }
      try {
        return new Input(path, snapshot.forApplicationModule(descriptor), null);
      } catch (final IOException exception) {
        return new Input(path, snapshot, null, exception.getMessage());
      }
    }
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static Path indexDirectory(final MavenSession session) {
    final MavenExecutionRequest request = session == null ? null : session.getRequest();
    final File repository = request == null ? null : request.getLocalRepositoryPath();
    return repository == null ? null : repository.toPath().resolve(".elider-runtime-index");
  }

  MavenRuntimePlatforms {
    inputs = List.copyOf(inputs);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static MavenRuntimePlatforms inspect(
      final Path projectBase, final List<String> configured, final MavenSession session) {
    final List<String> paths = configured == null ? List.of() : configured;
    final List<Path> inputs = paths.stream().map(input -> resolve(projectBase, input)).toList();
    final Map<Path, Input> images = new HashMap<>();
    final Path index = indexDirectory(session);
    return new MavenRuntimePlatforms(
        inputs.stream()
            .map(path -> images.computeIfAbsent(path, source -> read(source, index)))
            .toList());
  }

  private static Path resolve(final Path projectBase, final String input) {
    if (input == null || input.isBlank()) {
      throw new IllegalArgumentException("elide.runtimeInputs contains a blank runtime path");
    }
    final Path path = Path.of(input);
    if (path.isAbsolute()) {
      return path.normalize();
    }
    if (projectBase == null) {
      throw new IllegalArgumentException(
          "Relative runtime path needs a Maven project directory: " + input);
    }
    return projectBase.toAbsolutePath().resolve(path).normalize();
  }

  private static Input read(final Path path, final Path index) {
    try {
      return new Input(path, JdkPlatformContext.inspectRuntime(path, index), null);
    } catch (final IOException exception) {
      return new Input(path, null, exception.getMessage());
    }
  }

  List<PlatformSnapshot> available() {
    return inputs.stream()
        .flatMap(input -> Optional.ofNullable(input.platform()).stream())
        .toList();
  }

  OptionalInt highestInspectedRelease() {
    return available().stream().mapToInt(PlatformSnapshot::runtimeRelease).max();
  }

  MavenRuntimePlatforms forProductionOutput(final File output) throws IOException {
    if (output == null || inputs.isEmpty()) {
      return this;
    }
    final Path moduleInfo = output.toPath().resolve("module-info.class");
    if (!Files.isRegularFile(moduleInfo)) {
      return this;
    }
    final ModuleDescriptor descriptor;
    try (InputStream stream = Files.newInputStream(moduleInfo)) {
      descriptor = ModuleDescriptor.read(stream);
    } catch (final java.lang.module.InvalidModuleDescriptorException exception) {
      throw new IOException(
          "Cannot read the production module descriptor " + moduleInfo, exception);
    }
    return new MavenRuntimePlatforms(
        inputs.stream().map(input -> input.resolveModules(descriptor)).toList());
  }

  List<PlatformSnapshot> requireLinkage() throws IOException {
    if (inputs.isEmpty()) {
      throw new IOException("Configure elide.runtimeInputs to analyze platform linkage");
    }
    for (final Input input : inputs) {
      if (input.problem() != null) {
        throw new IOException(input.problem());
      }
      if (input.linkageProblem() != null) {
        throw new IOException(input.path() + ": " + input.linkageProblem());
      }
    }
    return available();
  }

  boolean hasLinkage() {
    return !inputs.isEmpty()
        && inputs.stream()
            .allMatch(input -> input.problem() == null && input.linkageProblem() == null);
  }

  String fingerprint() {
    return MavenElisionGraphBinding.sha256(
        inputs.stream()
            .map(
                input ->
                    input.path()
                        + "\n"
                        + (input.platform() == null
                            ? input.problem()
                            : input.platform().identity()))
            .sorted()
            .toList());
  }
}
