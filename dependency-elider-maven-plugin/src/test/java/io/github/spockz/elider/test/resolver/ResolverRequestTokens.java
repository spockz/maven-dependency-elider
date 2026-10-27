/* WHY: Lets the EventSpy and resolver probe compare request identity. */

package io.github.spockz.elider.test.resolver;

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.maven.project.DependencyResolutionRequest;

/** Shares request identity tokens among test-only core extension components. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
public final class ResolverRequestTokens {
  // Package access shares the token key between the fixture EventSpy and decorators.
  static final String REQUEST_TOKEN_KEY = "io.github.spockz.elider.test.resolver.request-token";

  // Identity keys separate request instances that have equal values.
  private static final Map<DependencyResolutionRequest, Integer> TOKENS = new IdentityHashMap<>();

  private static final ReentrantLock LOCK = new ReentrantLock();

  private static int sequence;

  private ResolverRequestTokens() {}

  /** Returns a stable token for a request object within this extension classloader. */
  public static int tokenFor(final DependencyResolutionRequest request) {
    LOCK.lock();
    try {
      Integer token = TOKENS.get(request);
      if (token == null) {
        sequence++;
        token = sequence;
        TOKENS.put(request, token);
      }
      return token;
    } finally {
      LOCK.unlock();
    }
  }
}
