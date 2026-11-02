// WHY: Resolves the invocation base from captured or request state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import java.io.File;
import java.nio.file.Path;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Resolves project and request base directories used by analysis inputs. */
final class MavenAnalysisInvocationBase {
  private MavenAnalysisInvocationBase() {
    throw new AssertionError("No instances");
  }

  static Path forProject(final MavenProject project, final AnalysisOptions options) {
    final File projectBase = project.getBasedir();
    if (options.environment() != null) {
      return options.environment().invocationBase() == null
          ? projectBasePath(projectBase)
          : options.environment().invocationBase();
    }
    return fromRequestBase(requestBase(options.session()), projectBase);
  }

  static Path fromRequest(final MavenExecutionRequest request, final File projectBase) {
    return fromRequestBase(requestBase(request), projectBase);
  }

  private static Path fromRequestBase(final String requestBase, final File projectBase) {
    if (requestBase != null && !requestBase.isBlank()) {
      return Path.of(requestBase).toAbsolutePath().normalize();
    }
    return projectBasePath(projectBase);
  }

  private static String requestBase(final MavenExecutionRequest request) {
    return request == null ? null : request.getBaseDirectory();
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  // WHY: MavenSession exposes the request that defines the invocation base.
  private static String requestBase(final MavenSession session) {
    if (session == null) {
      return null;
    }
    final MavenExecutionRequest request = session.getRequest();
    return request == null ? null : request.getBaseDirectory();
  }

  private static Path projectBasePath(final File projectBase) {
    if (projectBase == null) {
      return null;
    }
    final Path path = projectBase.toPath();
    return path.toAbsolutePath().normalize();
  }
}
