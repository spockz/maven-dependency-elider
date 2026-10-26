/* WHY: Proves Maven request data survives parallel session clones and scopes immutable platform
 * snapshots to one Maven execution without leaking them across independent executions. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.DoNotUseThreads",
  "PMD.AtLeastOneConstructor"
})
class MavenPlatformContextHolderTest {
  private static final int RELEASE = 21;
  private static final String CT_SYM_ENTRY = "L/java.base/fixture/Api.sig";

  @TempDir Path temporaryDirectory;

  @Test
  @DisplayName("ADR-0003: Maven 3.9.11 session clones share request-scoped contexts")
  void sessionClonesShareRequestScopedContext() throws Exception {
    final MavenSession session = session(new DefaultMavenExecutionRequest());
    final MavenSession clone = session.clone();
    final Path javaHome = javaHome("clone-sharing");

    try (JdkPlatformContext original = MavenPlatformContextHolder.forOperation(session, javaHome);
        JdkPlatformContext other =
            MavenPlatformContextHolder.forOperation(session, javaHome.resolve("other"))) {
      assertThat(clone.getRequest()).isSameAs(session.getRequest());
      assertThat(MavenPlatformContextHolder.forOperation(clone, javaHome)).isSameAs(original);
      assertThat(other).isNotSameAs(original);
    }
  }

  @Test
  @DisplayName("ADR-0003: standalone calls get fresh operation-scoped snapshot contexts")
  void standaloneCallsDoNotShareContexts() throws Exception {
    final Path javaHome = javaHome("standalone-context");
    try (JdkPlatformContext first = MavenPlatformContextHolder.forOperation(null, javaHome);
        JdkPlatformContext second = MavenPlatformContextHolder.forOperation(null, javaHome)) {
      assertThat(first).isNotSameAs(second);
    }
  }

  @Test
  @DisplayName("ADR-0003: independent Maven requests receive isolated contexts and recapture bytes")
  void independentRequestsRecaptureChangedSource() throws Exception {
    final Path javaHome = javaHome("request-isolation");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeCtSym(ctSym, CT_SYM_ENTRY, new byte[] {1});
    final MavenSession firstSession = session(new DefaultMavenExecutionRequest());
    final MavenSession secondSession = session(new DefaultMavenExecutionRequest());
    try (JdkPlatformContext first =
        MavenPlatformContextHolder.forOperation(firstSession, javaHome)) {
      final String firstIdentity = first.snapshot(RELEASE).identity();
      final long size = Files.size(ctSym);
      final FileTime timestamp = Files.getLastModifiedTime(ctSym);

      writeCtSym(ctSym, CT_SYM_ENTRY, new byte[] {2});
      Files.setLastModifiedTime(ctSym, timestamp);
      assertThat(Files.size(ctSym)).isEqualTo(size);

      try (JdkPlatformContext second =
          MavenPlatformContextHolder.forOperation(secondSession, javaHome)) {
        assertThat(second).isNotSameAs(first);
        assertThat(second.snapshot(RELEASE).identity()).isNotEqualTo(firstIdentity);
      }
    }
  }

  @Test
  @DisplayName("ADR-0003: parallel session clones publish one complete same-key snapshot")
  void parallelClonesShareCompleteSnapshot() throws Exception {
    final Path javaHome = javaHome("parallel-capture");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeCtSym(ctSym, CT_SYM_ENTRY, new byte[] {1, 2, 3});
    final MavenSession session = session(new DefaultMavenExecutionRequest());
    try (ExecutorService executor = Executors.newFixedThreadPool(8)) {
      final CountDownLatch ready = new CountDownLatch(8);
      final CountDownLatch start = new CountDownLatch(1);
      final List<Future<JdkPlatformContext.PlatformSnapshot>> results = new ArrayList<>();
      for (int index = 0; index < 8; index++) {
        final MavenSession clone = session.clone();
        results.add(
            executor.submit(
                () -> {
                  ready.countDown();
                  start.await();
                  return MavenPlatformContextHolder.forOperation(clone, javaHome).snapshot(RELEASE);
                }));
      }
      ready.await();
      start.countDown();
      final JdkPlatformContext.PlatformSnapshot published = results.getFirst().get();
      for (final Future<JdkPlatformContext.PlatformSnapshot> result : results) {
        assertThat(result.get()).isSameAs(published);
      }
      assertThat(published.sourceIdentities()).hasSize(1);
      assertThat(published.sourceIdentities().getFirst().sourcePath()).isEqualTo(ctSym);
    }
  }

  @Test
  @DisplayName("ADR-0003: failed same-request capture publishes nothing and can retry")
  void failedCaptureRetriesInSameRequest() throws Exception {
    final Path javaHome = javaHome("retry-capture");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    Files.writeString(ctSym, "not-a-zip");
    try (JdkPlatformContext context =
        MavenPlatformContextHolder.forOperation(
            session(new DefaultMavenExecutionRequest()), javaHome)) {

      assertThatThrownBy(() -> context.snapshot(RELEASE)).isInstanceOf(IOException.class);
      writeCtSym(ctSym, CT_SYM_ENTRY, new byte[] {1});
      assertThat(context.snapshot(RELEASE).sourceIdentities()).hasSize(1);
    }
  }

  private MavenSession session(final MavenExecutionRequest request) {
    return new MavenSession(null, request, null, new MavenProject());
  }

  private Path javaHome(final String name) throws IOException {
    final Path home = temporaryDirectory.resolve(name);
    Files.createDirectories(home.resolve("lib"));
    return home;
  }

  private static void writeCtSym(final Path path, final String entryName, final byte[] content)
      throws IOException {
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      output.putNextEntry(new ZipEntry(entryName));
      output.write(content);
      output.closeEntry();
    }
  }
}
