/* WHY: Shares immutable snapshots across Maven session clones. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;

/** Resolves request-scoped platform snapshot contexts. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPlatformContextHolder {
  /** Private execution-request slot for this plugin's invocation context map. */
  private static final String REQUEST_DATA_KEY = MavenPlatformContextHolder.class.getName();

  private MavenPlatformContextHolder() {}

  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidSynchronizedStatement"})
  static JdkPlatformContext forOperation(final MavenSession session, final Path javaHome) {
    if (session == null) {
      return new JdkPlatformContext(javaHome);
    }
    final MavenExecutionRequest request = session.getRequest();
    if (request == null) {
      throw new IllegalStateException("Maven session has no execution request");
    }
    synchronized (request) {
      final Map<String, Object> requestData = request.getData();
      final Object existing = requestData.get(REQUEST_DATA_KEY);
      final Contexts contexts;
      if (existing == null) {
        contexts = new Contexts();
        requestData.put(REQUEST_DATA_KEY, contexts);
      } else if (existing instanceof Contexts stored) {
        contexts = stored;
      } else {
        throw new IllegalStateException("Maven execution request data key is already occupied");
      }
      return contexts.forJavaHome(javaHome);
    }
  }

  private record ContextKey(Path javaHome, String readerPolicy) {}

  /** Stores one mutable context owner per normalized JDK and reader policy. */
  private static final class Contexts {
    /** Contexts retained for this Maven request lifetime. */
    private final Map<ContextKey, JdkPlatformContext> byJavaHome = new ConcurrentHashMap<>();

    JdkPlatformContext forJavaHome(final Path javaHome) {
      final ContextKey key =
          new ContextKey(
              javaHome.toAbsolutePath().normalize(), JdkPlatformContext.READER_POLICY_VERSION);
      return byJavaHome.computeIfAbsent(key, ignored -> new JdkPlatformContext(key.javaHome()));
    }
  }
}
