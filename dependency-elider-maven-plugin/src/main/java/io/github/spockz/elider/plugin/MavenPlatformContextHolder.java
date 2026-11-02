/* WHY: Shares immutable active-runtime module templates across Maven session clones. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.util.Map;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;

/** Resolves invocation-scoped platform snapshot contexts. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPlatformContextHolder {
  /** Private execution-request slot for this plugin's invocation context. */
  private static final String REQUEST_DATA_KEY = MavenPlatformContextHolder.class.getName();

  private MavenPlatformContextHolder() {}

  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidSynchronizedStatement"})
  static JdkPlatformContext forOperation(final MavenSession session) {
    if (session == null) {
      return new JdkPlatformContext();
    }
    final MavenExecutionRequest request = session.getRequest();
    if (request == null) {
      throw new IllegalStateException("Maven session has no execution request");
    }
    synchronized (request) {
      final Map<String, Object> requestData = request.getData();
      final Object existing = requestData.get(REQUEST_DATA_KEY);
      if (existing == null) {
        final JdkPlatformContext context = new JdkPlatformContext();
        requestData.put(REQUEST_DATA_KEY, context);
        return context;
      }
      if (existing instanceof JdkPlatformContext context) {
        return context;
      }
      throw new IllegalStateException("Maven execution request data key is already occupied");
    }
  }
}
