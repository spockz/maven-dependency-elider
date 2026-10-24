// WHY: Reads JAR class names from ZIP metadata so dependency pruning avoids inflating bytecode.

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Scans JAR central directories without reading entry contents. */
@SuppressWarnings({"PMD.DoNotUseThreads", "PMD.PreserveStackTrace"})
public final class JarIndexScanner {
  /** Creates a scanner that uses virtual threads for artifact scans. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JarIndexScanner() {}

  /** Scans all artifact JARs concurrently using Java virtual threads. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  public ArtifactClassIndex scan(final Collection<ArtifactFileRef> artifacts) throws IOException {
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      final List<Future<Map.Entry<ArtifactFileRef, Set<String>>>> futures = new ArrayList<>();
      for (final ArtifactFileRef artifact : artifacts) {
        futures.add(executor.submit(() -> Map.entry(artifact, scanJar(artifact.filePath()))));
      }
      final Map<ArtifactFileRef, Set<String>> classesByArtifact = new java.util.LinkedHashMap<>();
      for (final Future<Map.Entry<ArtifactFileRef, Set<String>>> future : futures) {
        try {
          final Map.Entry<ArtifactFileRef, Set<String>> result = future.get();
          classesByArtifact.put(result.getKey(), result.getValue());
        } catch (final InterruptedException exception) {
          Thread.currentThread().interrupt();
          throw new IOException("Interrupted while scanning artifact JARs", exception);
        } catch (final ExecutionException exception) {
          final Throwable cause = exception.getCause();
          if (cause instanceof IOException ioException) {
            throw ioException;
          }
          throw new IOException("Failed to scan artifact JAR", cause);
        }
      }
      return new ArtifactClassIndex(classesByArtifact);
    }
  }

  /** Offers a serial option for callers avoiding virtual-thread scheduling. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  public ArtifactClassIndex scanSequential(final Collection<ArtifactFileRef> artifacts)
      throws IOException {
    final Map<ArtifactFileRef, Set<String>> classesByArtifact = new java.util.LinkedHashMap<>();
    for (final ArtifactFileRef artifact : artifacts) {
      classesByArtifact.put(artifact, scanJar(artifact.filePath()));
    }
    return new ArtifactClassIndex(classesByArtifact);
  }

  private static Set<String> scanJar(final Path jarPath) throws IOException {
    final Set<String> classes = new HashSet<>();
    try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
      final java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        final String name = entry.getName();
        if (!entry.isDirectory() && name.endsWith(".class")) {
          final String classPath = logicalClassPath(name);
          if (classPath != null && !isModuleInfo(classPath)) {
            classes.add(TraceData.normalizeToDot(classPath));
          }
        }
      }
    }
    return Set.copyOf(classes);
  }

  private static String logicalClassPath(final String entryName) {
    final String versionsPrefix = "META-INF/versions/";
    if (!entryName.startsWith(versionsPrefix)) {
      return entryName;
    }
    final int versionEnd = entryName.indexOf('/', versionsPrefix.length());
    if (versionEnd < 0 || versionEnd == entryName.length() - 1) {
      return null;
    }
    return entryName.substring(versionEnd + 1);
  }

  private static boolean isModuleInfo(final String classPath) {
    return "module-info.class".equals(classPath);
  }
}
