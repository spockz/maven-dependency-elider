/* WHY: Reads HotSpot CDS class-list dumps as a compact, normalized source of classes loaded by an
 * application. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Reads HotSpot {@code -XX:DumpLoadedClassList} files. */
public final class CdsClassListReader implements RuntimeTraceReader {
  /** Creates a reader for HotSpot CDS class-list files. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public CdsClassListReader() {}

  /** Recognizes conventional {@code .lst} CDS class-list paths. */
  @Override
  public boolean supports(final Path path) {
    if (path == null) {
      return false;
    }
    final Path fileName = path.getFileName();
    return fileName != null && fileName.toString().toLowerCase(Locale.ROOT).endsWith(".lst");
  }

  /** Reads slash-separated class names, skipping blank and comment lines. */
  @Override
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported CDS class-list file: " + path);
    }
    final Set<String> classes = new HashSet<>();
    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      while (true) {
        final String line = reader.readLine();
        if (line == null) {
          break;
        }
        collectClassName(line, classes);
      }
    }
    return TraceData.of(classes);
  }

  private static void collectClassName(final String line, final Set<String> classes)
      throws IOException {
    final String candidate = line.trim();
    if (candidate.isEmpty() || candidate.startsWith("#") || candidate.startsWith("@")) {
      return;
    }
    if (!TraceClassName.isValid(candidate) || TraceClassName.isHidden(candidate)) {
      throw new IOException("Malformed CDS class-list entry: " + candidate);
    }
    classes.add(candidate);
  }
}
