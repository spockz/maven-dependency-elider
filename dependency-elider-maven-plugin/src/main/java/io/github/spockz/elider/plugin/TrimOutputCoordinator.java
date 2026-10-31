/* WHY: Chooses direct or generation-based output execution while keeping
 * archive publication in canonical order. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;

/** Selects direct or effective output publication. */
final class TrimOutputCoordinator {
  private TrimOutputCoordinator() {}

  /* package */ static TrimResult trimPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext)
      throws IOException, MojoFailureException {
    return trimPrepared(request, release, runtimeRelease, platformContext, null);
  }

  /* package */ static TrimResult trimPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext,
      final EffectiveOutputPlan effectiveOutput)
      throws IOException, MojoFailureException {
    if (effectiveOutput != null) {
      return EffectiveTrimOutput.trimEffectivePrepared(
          request, release, runtimeRelease, platformContext, effectiveOutput);
    }
    return DirectTrimOutput.trimDirectPrepared(request, release, runtimeRelease, platformContext);
  }

  /* package */ record PendingOutput(
      TrimCandidate candidate, ArchiveSanitizer.PreparedOutput prepared) {}

  /* package */ static List<ArtifactTrimRecord> publishOutputs(
      final List<ArchiveSanitizer.PreparedOutput> preparedOutputs,
      final PreparedOutputPublisher publisher)
      throws IOException {
    final List<ArtifactTrimRecord> records = new ArrayList<>(preparedOutputs.size());
    for (final ArchiveSanitizer.PreparedOutput prepared : preparedOutputs) {
      records.add(publisher.publish(prepared));
    }
    return List.copyOf(records);
  }
}
