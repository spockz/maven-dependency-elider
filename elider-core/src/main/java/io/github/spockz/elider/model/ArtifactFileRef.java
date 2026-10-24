package io.github.spockz.elider.model;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/** Holds an artifact path and cache metadata used to detect file changes. */
public record ArtifactFileRef(
    ArtifactCoordinate coordinate, Path filePath, long lastModified, long fileSize) {
  /** Requires the artifact identity and file path needed for cache fingerprinting. */
  public ArtifactFileRef {
    Objects.requireNonNull(coordinate, "coordinate must not be null");
    Objects.requireNonNull(filePath, "filePath must not be null");
  }

  /** Reads current file metadata and fails when the artifact cannot be inspected. */
  public static ArtifactFileRef fromPath(final ArtifactCoordinate coordinate, final Path filePath)
      throws IOException {
    Objects.requireNonNull(coordinate, "coordinate must not be null");
    Objects.requireNonNull(filePath, "filePath must not be null");
    final BasicFileAttributes attributes =
        java.nio.file.Files.readAttributes(filePath, BasicFileAttributes.class);
    return new ArtifactFileRef(
        coordinate, filePath, attributes.lastModifiedTime().toMillis(), attributes.size());
  }
}
