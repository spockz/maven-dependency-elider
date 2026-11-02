// WHY: Rechecks original audit inventory and bytes at every ban freshness boundary.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Verifies frozen original-audit inputs still match the current Maven project. */
final class MavenBanAuditFreshnessVerifier {
  private MavenBanAuditFreshnessVerifier() {}

  /* package */ static void verify(
      final MavenBanAuditContext auditContext,
      final MavenProject project,
      final MavenSession session)
      throws IOException {
    auditContext.verifyArtifactBytes();
    if (auditContext.inventory() != null) {
      MavenOriginalInputAudit.verifyCaptureFresh(auditContext.inventory(), project, session);
    }
  }
}
