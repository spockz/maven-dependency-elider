/* WHY: Reuses parsed modular runtime declarations across builds with the same input bytes. */

package io.github.spockz.elider.trimmer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.trimmer.JdkPlatformContext.CapturedModule;
import io.github.spockz.elider.trimmer.JdkPlatformContext.ModuleIdentity;
import io.github.spockz.elider.trimmer.JdkPlatformContext.PlatformSnapshot;
import io.github.spockz.elider.trimmer.JdkPlatformContext.RuntimeMetadata;
import java.io.IOException;
import java.lang.module.ModuleDescriptor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
record RuntimePlatformIndex(Path directory, String imageKey) {
  private static final int SCHEMA_VERSION = 1;
  private static final ObjectMapper MAPPER =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);

  PlatformSnapshot load(final RuntimeMetadata metadata, final String imageDigest) {
    try (GZIPInputStream source = new GZIPInputStream(Files.newInputStream(indexPath()))) {
      return readImage(source).snapshot(metadata, imageDigest);
    } catch (final IOException
        | IllegalArgumentException
        | java.lang.module.InvalidModuleDescriptorException exception) {
      System.getLogger(RuntimePlatformIndex.class.getName())
          .log(System.Logger.Level.DEBUG, "Runtime index unavailable at " + indexPath(), exception);
      return null;
    }
  }

  private CachedImage readImage(final GZIPInputStream source) throws IOException {
    final CachedImage image = MAPPER.readValue(source, CachedImage.class);
    if (image == null
        || image.schemaVersion() != SCHEMA_VERSION
        || !imageKey.equals(image.imageKey())) {
      throw new IOException("Runtime index identity mismatch");
    }
    return image;
  }

  void store(final PlatformSnapshot platform) {
    try {
      Files.createDirectories(directory);
      final Path staging = Files.createTempFile(directory, "pending-", ".json.gz");
      try {
        final CachedImage image =
            new CachedImage(
                SCHEMA_VERSION,
                imageKey,
                platform.capturedModules().stream().map(CachedModule::fromCaptured).toList());
        try (GZIPOutputStream stream = new GZIPOutputStream(Files.newOutputStream(staging))) {
          MAPPER.writeValue(stream, image);
        }
        Files.move(staging, indexPath(), StandardCopyOption.REPLACE_EXISTING);
      } finally {
        Files.deleteIfExists(staging);
      }
    } catch (final IOException exception) {
      System.getLogger(RuntimePlatformIndex.class.getName())
          .log(System.Logger.Level.DEBUG, "Cannot write runtime index " + indexPath(), exception);
    }
  }

  private Path indexPath() {
    return directory.resolve(imageKey + ".json.gz");
  }

  private record CachedImage(int schemaVersion, String imageKey, List<CachedModule> modules) {
    private CachedImage {
      modules = List.copyOf(modules);
    }

    private PlatformSnapshot snapshot(final RuntimeMetadata metadata, final String imageDigest)
        throws IOException {
      final List<ModuleDescriptor> descriptors = new ArrayList<>(modules.size());
      final List<CapturedModule> captured = new ArrayList<>(modules.size());
      String previous = "";
      for (final CachedModule module : modules) {
        final ModuleDescriptor descriptor = module.descriptor();
        final ModuleIdentity identity = module.identity();
        if (previous.compareTo(descriptor.name()) >= 0
            || !descriptor.name().equals(identity.moduleName())
            || identity.classCount() != module.classes().size()
            || identity.byteCount() <= 0) {
          throw new IOException("Invalid runtime module index: " + descriptor.name());
        }
        HexDigest.requireSha256(identity.sha256(), "Runtime module digest");
        previous = descriptor.name();
        descriptors.add(descriptor);
        captured.add(module.materialize());
      }
      if (descriptors.stream().noneMatch(descriptor -> "java.base".equals(descriptor.name()))) {
        throw new IOException("Runtime index has no java.base module");
      }
      return PlatformSnapshot.fromIndex(metadata, captured, descriptors, imageDigest);
    }
  }

  private record CachedModule(
      ModuleIdentity identity, String descriptorBytes, List<LibraryClassTemplate> classes) {
    private CachedModule {
      Objects.requireNonNull(identity, "Module identity");
      Objects.requireNonNull(descriptorBytes, "Module descriptor");
      classes = List.copyOf(classes);
    }

    private static CachedModule fromCaptured(final CapturedModule module) {
      return new CachedModule(
          module.identity(),
          module.descriptorBytes(),
          module.classes().stream().map(LibraryClassTemplate::from).toList());
    }

    private ModuleDescriptor descriptor() {
      return RuntimeModuleFinder.readDescriptor(Base64.getDecoder().decode(descriptorBytes));
    }

    private CapturedModule materialize() {
      return new CapturedModule(
          identity,
          descriptorBytes,
          classes.stream().map(LibraryClassTemplate::materialize).toList());
    }
  }
}
