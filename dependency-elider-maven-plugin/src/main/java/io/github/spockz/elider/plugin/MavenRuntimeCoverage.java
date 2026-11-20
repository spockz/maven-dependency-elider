/* WHY: Persists runtime inspection evidence for later report replay without re-opening inputs. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.trimmer.JdkPlatformContext.PlatformSnapshot;
import io.github.spockz.elider.trimmer.JdkPlatformContext.RuntimeMetadata;
import java.util.List;

@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
record MavenRuntimeCoverage(
    List<Image> inputs,
    List<Integer> analyzedReleases,
    boolean compilerTargetExplicit,
    String compilerTargetWarning) {
  static final MavenRuntimeCoverage EMPTY =
      new MavenRuntimeCoverage(List.of(), List.of(), false, null);

  record Image(
      String path,
      Integer feature,
      String version,
      String vendor,
      String implementation,
      String operatingSystem,
      String architecture,
      String contentIdentity,
      String problem,
      String linkageProblem) {
    Image {
      if (path == null || path.isBlank()) {
        throw new IllegalArgumentException("Runtime input path is required");
      }
      if (problem == null) {
        if (feature == null
            || version == null
            || contentIdentity == null
            || Runtime.Version.parse(version).feature() != feature) {
          throw new IllegalArgumentException(
              "Inspected runtime input requires matching version and identity");
        }
        HexDigest.requireSha256(contentIdentity, "Runtime content identity");
        if (linkageProblem != null && linkageProblem.isBlank()) {
          throw new IllegalArgumentException("Runtime linkage diagnostic cannot be blank");
        }
      } else if (problem.isBlank()
          || feature != null
          || version != null
          || contentIdentity != null
          || linkageProblem != null) {
        throw new IllegalArgumentException(
            "Unavailable runtime input cannot claim inspection identity");
      }
    }
  }

  MavenRuntimeCoverage {
    inputs = List.copyOf(inputs);
    analyzedReleases = List.copyOf(analyzedReleases);
    if (!analyzedReleases.isEmpty()
        && (!analyzedReleases.equals(inspectedReleases(inputs))
            || inputs.stream()
                .anyMatch(image -> image.feature() == null || image.linkageProblem() != null))) {
      throw new IllegalArgumentException(
          "Analyzed runtime releases require resolved linkage for all supplied images and"
              + " releases");
    }
    if (compilerTargetWarning != null
        && (!compilerTargetExplicit || compilerTargetWarning.isBlank())) {
      throw new IllegalArgumentException(
          "A runtime coverage warning requires a configured compiler target");
    }
  }

  static MavenRuntimeCoverage from(
      final MavenRuntimePlatforms selected,
      final int target,
      final boolean explicit,
      final List<Integer> analyzed) {
    if (selected == null) {
      return EMPTY;
    }
    final List<Image> inputs =
        selected.inputs().stream().map(MavenRuntimeCoverage::describe).toList();
    return new MavenRuntimeCoverage(
        inputs, analyzed, explicit, coverageWarning(target, explicit, inputs, analyzed));
  }

  String expectedCompilerTargetWarning(final int target) {
    return coverageWarning(target, compilerTargetExplicit, inputs, analyzedReleases);
  }

  private static String coverageWarning(
      final int target,
      final boolean explicit,
      final List<Image> inputs,
      final List<Integer> analyzed) {
    if (!explicit) {
      return null;
    }
    final List<Integer> inspected = inspectedReleases(inputs);
    if (inspected.contains(target)) {
      return null;
    }
    final String coverage;
    if (inspected.isEmpty()) {
      coverage = "no runtime inspected";
    } else if (analyzed.isEmpty()) {
      coverage = "no runtime releases analyzed";
    } else {
      coverage = "analysis covers " + analyzed;
    }
    return "Compiler target Java "
        + target
        + " is not covered by supplied runtime releases "
        + inspected
        + " ("
        + coverage
        + ").";
  }

  private static List<Integer> inspectedReleases(final List<Image> inputs) {
    return inputs.stream()
        .map(Image::feature)
        .filter(java.util.Objects::nonNull)
        .distinct()
        .sorted()
        .toList();
  }

  private static Image describe(final MavenRuntimePlatforms.Input input) {
    final PlatformSnapshot snapshot = input.platform();
    final String path = input.path().toString();
    if (snapshot == null) {
      return new Image(path, null, null, null, null, null, null, null, input.problem(), null);
    }
    final RuntimeMetadata metadata = snapshot.metadata();
    return new Image(
        path,
        snapshot.runtimeRelease(),
        snapshot.runtimeVersion().toString(),
        metadata.vendor(),
        metadata.implementation(),
        metadata.operatingSystem(),
        metadata.architecture(),
        MavenElisionGraphBinding.sha256(List.of(snapshot.identity())),
        null,
        input.linkageProblem());
  }
}
