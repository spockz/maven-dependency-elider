// WHY: Prevents Javac service discovery from loading application or artifact plugins.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;

/** Restricts classpath processor discovery to the platform loader. */
final class IsolatedProcessorPathFileManager
    extends ForwardingJavaFileManager<StandardJavaFileManager> {
  /** The compiler task must receive exactly one explicit unit. */
  private static final int ONE_EXPLICIT_SOURCE_UNIT = 1;

  /* default */ IsolatedProcessorPathFileManager(final StandardJavaFileManager fileManager) {
    super(fileManager);
  }

  /* default */ void setEmptyProcessorPath(final Path emptyProcessorPath) throws IOException {
    fileManager.setLocationFromPaths(
        StandardLocation.ANNOTATION_PROCESSOR_PATH, List.of(emptyProcessorPath));
  }

  /* default */ List<JavaFileObject> sourceUnits(final Path source) throws IOException {
    final List<JavaFileObject> units =
        java.util.stream.StreamSupport.stream(
                fileManager.getJavaFileObjects(source.toFile()).spliterator(), false)
            .map(JavaFileObject.class::cast)
            .toList();
    if (units.size() != ONE_EXPLICIT_SOURCE_UNIT) {
      throw new IOException("Expected one explicit source unit: " + source);
    }
    return units;
  }

  @Override
  public ClassLoader getClassLoader(final Location location) {
    if (location == StandardLocation.ANNOTATION_PROCESSOR_PATH) {
      return ClassLoader.getPlatformClassLoader();
    }
    return super.getClassLoader(location);
  }
}
