/* WHY: Reads modular images through the host provider without running the selected runtime. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.trimmer.JdkPlatformContext.PlatformSnapshot;
import io.github.spockz.elider.trimmer.JdkPlatformContext.RuntimeMetadata;
import io.github.spockz.elider.trimmer.JdkPlatformContext.RuntimeTool;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

@SuppressWarnings({
  "PMD.CouplingBetweenObjects",
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap",
  "PMD.TooManyMethods",
  "PMD.GodClass"
})
final class RuntimeImageReader implements AutoCloseable {
  private static final URI JRT = URI.create("jrt:/");
  private static final String RELEASE = "release";
  private static final String MODULES = "lib/modules";
  private static final String JRT_PROVIDER = "lib/jrt-fs.jar";
  private static final String METADATA_VERSION = "JAVA_VERSION";
  private static final String BUILD_VERSION = "JAVA_RUNTIME_VERSION";
  private static final int MINIMUM_RUNTIME = 9;
  private static final int MAXIMUM_RELEASE_BYTES = 64 * 1024;

  private final Path source;
  private final Path workspace;

  private RuntimeImageReader(final Path source) throws IOException {
    this.source = source;
    workspace = Files.createTempDirectory("elider-platform-");
  }

  static PlatformSnapshot inspect(final Path input, final Path indexDirectory) throws IOException {
    final Path source = input.toAbsolutePath().normalize();
    try (RuntimeImageReader reader = new RuntimeImageReader(source)) {
      return reader.inspectImage(indexDirectory);
    } catch (final IOException
        | IllegalArgumentException
        | java.lang.module.InvalidModuleDescriptorException
        | java.io.UncheckedIOException exception) {
      throw new IOException(
          "Cannot inspect runtime " + source + ": " + exception.getMessage(), exception);
    } catch (final java.nio.file.ProviderNotFoundException
        | UnsupportedOperationException
        | LinkageError exception) {
      throw new IOException("Runtime image access is unavailable for " + source, exception);
    }
  }

  static <T> T withInstalledRuntimeForTool(final Path input, final RuntimeTool<T> tool)
      throws IOException {
    try (RuntimeImageReader reader = new RuntimeImageReader(input.toAbsolutePath().normalize())) {
      final Path home = reader.installedHome();
      final Path workspace = reader.workspace;
      Files.createDirectory(workspace.resolve("lib"));
      reader.stageInstalledModules(home);
      reader.stageTrustedProvider();
      Files.copy(home.resolve(RELEASE), workspace.resolve(RELEASE));
      return tool.use(workspace);
    }
  }

  private PlatformSnapshot inspectImage(final Path indexDirectory) throws IOException {
    Files.createDirectory(workspace.resolve("lib"));
    final PreparedImage prepared = prepare();
    final RuntimeMetadata metadata = metadata(prepared.properties());
    final RuntimePlatformIndex index =
        indexDirectory == null ? null : index(indexDirectory, prepared, metadata);
    if (index != null) {
      final PlatformSnapshot cached = index.load(metadata, prepared.modulesDigest());
      if (cached != null) {
        return cached;
      }
    }
    final PlatformSnapshot platform = inspectModules(metadata, prepared.modulesDigest());
    if (index != null) {
      index.store(platform);
    }
    return platform;
  }

  private static RuntimePlatformIndex index(
      final Path directory, final PreparedImage prepared, final RuntimeMetadata metadata) {
    final String key =
        HexDigest.sha256(
            JdkPlatformContext.READER_POLICY_VERSION
                + "\n"
                + JdkPlatformContext.RuntimeMetadata.active()
                + "\n"
                + metadata
                + "\n"
                + prepared.modulesDigest());
    return new RuntimePlatformIndex(directory, key);
  }

  private PlatformSnapshot inspectModules(final RuntimeMetadata metadata, final String imageDigest)
      throws IOException {
    stageTrustedProvider();
    try (FileSystem image =
        FileSystems.newFileSystem(JRT, Map.of("java.home", workspace.toString()))) {
      final RuntimeModuleFinder finder = RuntimeModuleFinder.read(image.getPath("/modules"));
      finder.validateVersion(metadata.version());
      return JdkPlatformContext.inspectModules(finder, metadata, imageDigest);
    }
  }

  private void stageTrustedProvider() throws IOException {
    final Path localProvider = Path.of(System.getProperty("java.home")).resolve(JRT_PROVIDER);
    if (!Files.isRegularFile(localProvider)) {
      throw new IOException("Maven's JDK does not supply a supported jrt provider");
    }
    Files.copy(localProvider, workspace.resolve(JRT_PROVIDER));
  }

  private record PreparedImage(Properties properties, String modulesDigest) {}

  private PreparedImage prepare() throws IOException {
    if (Files.isDirectory(source)) {
      return prepareInstallation();
    }

    if (!Files.isRegularFile(source)) {
      throw new IOException("Runtime input does not exist");
    }
    final String filename = source.toFile().getName().toLowerCase(java.util.Locale.ROOT);
    final ArchiveRuntimeContents contents = new ArchiveRuntimeContents(workspace.resolve(MODULES));
    if (filename.endsWith(".zip")) {
      readZip(contents);
    } else if (filename.endsWith(".tar.gz") || filename.endsWith(".tgz")) {
      readTar(contents);
    } else {
      throw new IOException("Expected a modular runtime home, ZIP or tar.gz");
    }
    return new PreparedImage(contents.releaseProperties(), contents.modulesDigest);
  }

  private PreparedImage prepareInstallation() throws IOException {
    final Path home = installedHome();
    final Path modules = stageInstalledModules(home);
    return new PreparedImage(readProperties(home.resolve(RELEASE)), HexDigest.sha256(modules));
  }

  private Path installedHome() {
    final Path nested = source.resolve("Contents/Home");
    return Files.isDirectory(nested) ? nested : source;
  }

  private Path stageInstalledModules(final Path home) throws IOException {
    final Path installedModules = home.resolve(MODULES);
    if (!Files.isRegularFile(installedModules)) {
      throw new IOException("Runtime home has no " + MODULES);
    }
    try {
      Files.createSymbolicLink(workspace.resolve(MODULES), installedModules);
    } catch (IOException | UnsupportedOperationException noLinks) {
      Files.copy(installedModules, workspace.resolve(MODULES));
    }
    return installedModules;
  }

  private void readZip(final ArchiveRuntimeContents contents) throws IOException {
    final int expectedEntries;
    try (ZipFile directory = new ZipFile(source.toFile())) {
      expectedEntries = directory.size();
    }
    try (ZipInputStream archive = new ZipInputStream(Files.newInputStream(source))) {
      int entries = 0;
      ZipEntry entry = archive.getNextEntry();
      while (entry != null) {
        entries++;
        if (!entry.isDirectory() && ArchiveRuntimeContents.isRuntimeEntry(entry.getName())) {
          contents.accept(entry.getName(), archive);
        }
        entry = archive.getNextEntry();
      }
      if (entries != expectedEntries) {
        throw new IOException("ZIP entries do not match its central directory");
      }
    }
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private void readTar(final ArchiveRuntimeContents contents) throws IOException {
    try (InputStream stream = Files.newInputStream(source);
        GZIPInputStream gzip = new GZIPInputStream(stream);
        TarArchiveInputStream archive = new TarArchiveInputStream(gzip)) {
      TarArchiveEntry entry = archive.getNextEntry();
      while (entry != null) {
        if (entry.isFile() && ArchiveRuntimeContents.isRuntimeEntry(entry.getName())) {
          contents.accept(entry.getName(), archive);
        }
        entry = archive.getNextEntry();
      }
      // TAR can finish before gzip verifies the archive trailer.
      gzip.transferTo(OutputStream.nullOutputStream());
    }
  }

  private static Properties readProperties(final Path releaseFile) throws IOException {
    if (!Files.isRegularFile(releaseFile)) {
      throw new IOException("Runtime home has no release metadata");
    }
    try (InputStream stream = Files.newInputStream(releaseFile)) {
      return loadProperties(stream);
    }
  }

  private static Properties loadProperties(final InputStream stream) throws IOException {
    final byte[] bytes = stream.readNBytes(MAXIMUM_RELEASE_BYTES + 1);
    if (bytes.length > MAXIMUM_RELEASE_BYTES) {
      throw new IOException("Runtime release metadata is too large");
    }
    final Properties properties = new Properties();
    properties.load(
        new java.io.StringReader(new String(bytes, java.nio.charset.StandardCharsets.UTF_8)));
    return properties;
  }

  private static RuntimeMetadata metadata(final Properties properties) throws IOException {
    final String featureVersion = property(properties, METADATA_VERSION);
    if (featureVersion == null) {
      throw new IOException("Runtime release metadata does not name " + METADATA_VERSION);
    }
    final String recordedBuild = property(properties, BUILD_VERSION);
    final Runtime.Version version = Runtime.Version.parse(featureVersion);
    final Runtime.Version fullVersion =
        recordedBuild == null ? version : Runtime.Version.parse(recordedBuild);
    if (version.feature() < MINIMUM_RUNTIME) {
      throw new IOException("Runtime is not a supported modular Java image: " + version);
    }
    if (!version.version().equals(fullVersion.version())) {
      throw new IOException("Runtime release and build versions disagree");
    }
    return new RuntimeMetadata(
        fullVersion,
        property(properties, "IMPLEMENTOR"),
        property(properties, "IMPLEMENTOR_VERSION"),
        property(properties, "OS_NAME"),
        property(properties, "OS_ARCH"));
  }

  private static String property(final Properties properties, final String name) {
    final String value = properties.getProperty(name);
    if (value == null) {
      return null;
    }
    final String unquoted =
        value.startsWith("\"") && value.endsWith("\"") && value.length() > 1
            ? value.substring(1, value.length() - 1)
            : value;
    return unquoted.isBlank() ? null : unquoted;
  }

  @Override
  public void close() throws IOException {
    final List<Path> paths;
    try (java.util.stream.Stream<Path> workspacePaths = Files.walk(workspace)) {
      paths = workspacePaths.sorted(Comparator.reverseOrder()).toList();
    }
    for (final Path path : paths) {
      Files.delete(path);
    }
  }

  private static final class ArchiveRuntimeContents {
    private final Path outputModules;
    private final Map<String, Properties> releases = new java.util.HashMap<>();
    private String imageRoot;
    private String modulesDigest;

    private ArchiveRuntimeContents(final Path outputModules) {
      this.outputModules = outputModules;
    }

    private static boolean isRuntimeEntry(final String name) {
      return matches(name, RELEASE) || matches(name, MODULES);
    }

    private static boolean matches(final String name, final String relativePath) {
      return name.equals(relativePath) || name.endsWith("/" + relativePath);
    }

    private void accept(final String name, final InputStream contents) throws IOException {
      if (matches(name, MODULES)) {
        if (imageRoot != null) {
          throw new IOException("Archive contains multiple runtime images at " + name);
        }
        imageRoot = name.substring(0, name.length() - MODULES.length());
        final MessageDigest digest = ArtifactDigests.newSha256Digest();
        Files.copy(new DigestInputStream(contents, digest), outputModules);
        modulesDigest = HexFormat.of().formatHex(digest.digest());
      } else {
        final String releaseRoot = name.substring(0, name.length() - RELEASE.length());
        if (releases.putIfAbsent(releaseRoot, loadProperties(contents)) != null) {
          throw new IOException("Archive repeats runtime release metadata at " + name);
        }
      }
    }

    private Properties releaseProperties() throws IOException {
      if (imageRoot == null) {
        throw new IOException("Archive has no " + MODULES);
      }
      final Properties properties = releases.get(imageRoot);
      if (properties == null) {
        throw new IOException("Archive has no release metadata under " + imageRoot);
      }
      return properties;
    }
  }
}
