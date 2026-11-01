// WHY: Binds byte reproduction to the exact supported javac and JDK platform image.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Optional;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/** Identifies the supported JDK21 compiler and platform bytes. */
final class SourceJdkIdentity {
  /** Java release admitted by this initial source correspondence implementation. */
  private static final int SUPPORTED_FEATURE = 21;

  /** Compiler module used to ensure the loaded implementation is javac. */
  private static final String COMPILER_MODULE = "jdk.compiler";

  /** Vendor of the one reviewed compiler image. */
  private static final String SUPPORTED_VENDOR = "Oracle Corporation";

  /** Runtime build string belonging to the one reviewed compiler image. */
  private static final String SUPPORTED_RUNTIME = "21.0.12+7-LTS-jvmci-23.1-b96";

  /** Loaded JavacTool class bytes from the supported image. */
  private static final String SUPPORTED_JAVAC_CLASS_SHA256 =
      "4922e5aadd358c6d85ab0de3bab577cf22dd7b17ad043c1b01caa29db432c008";

  /** SHA-256 of the jdk.compiler module from the supported image. */
  private static final String SUPPORTED_COMPILER_IMAGE_SHA256 =
      "c9a397fb3facb651f0b6f99c347e9ae2322e06b9f7741ed1d9fcf6cbad642e08";

  /** Complete JDK module image bytes from the supported platform. */
  private static final String SUPPORTED_PLATFORM_IMAGE_SHA256 =
      "87ad8202e53b947dfafa4fbf0492f584ceb5ffcb6997560c085e63573c28c66b";

  /** --release API signature image bytes from the supported platform. */
  private static final String SUPPORTED_RELEASE_API_SHA256 =
      "fcd557bf5405e2c4ba71f66d91e508a08010c942cfdfc52d6adef34e8a84506a";

  private SourceJdkIdentity() {}

  @SuppressWarnings("PMD.ExceptionAsFlowControl") // Unsupported JDK images become explicit refusal.
  /* default */ static Resolution current() {
    try {
      final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
      if (compiler == null) {
        throw new IOException("JDK 21 javac is unavailable");
      }
      final Path javaHome = Path.of(System.getProperty("java.home")).toRealPath();
      final byte[] compilerClass = compilerClassBytes(compiler);
      final String value =
          create(
              Runtime.version().feature(),
              compiler.getClass().getModule().getName(),
              compilerClass,
              javaHome,
              new RuntimeMetadata(
                  System.getProperty("java.vendor"),
                  System.getProperty("java.runtime.version"),
                  System.getProperty("os.name"),
                  System.getProperty("os.arch"),
                  System.getProperty("os.version")));
      return requireSupportedIdentity(value);
    } catch (final IOException failure) {
      return Resolution.unavailable(failure.getMessage());
    }
  }

  /* default */ static String create(
      final int feature,
      final String compilerModule,
      final byte[] compilerClass,
      final Path javaHome,
      final RuntimeMetadata runtime)
      throws IOException {
    if (feature != SUPPORTED_FEATURE || !COMPILER_MODULE.equals(compilerModule)) {
      throw new IOException("Source reproduction requires the JDK 21 jdk.compiler module");
    }
    final Path compilerImage = javaHome.resolve("jmods/jdk.compiler.jmod");
    final Path platformImage = javaHome.resolve("lib/modules");
    final Path releaseApiImage = javaHome.resolve("lib/ct.sym");
    requireRegularFile(compilerImage, "JDK compiler image");
    requireRegularFile(platformImage, "JDK platform image");
    requireRegularFile(releaseApiImage, "JDK release API image");
    if (compilerClass == null || compilerClass.length == 0) {
      throw new IOException("Loaded javac implementation bytes are unavailable");
    }
    return String.join(
        ";",
        "feature=" + feature,
        "module=" + compilerModule,
        "vendor=" + requireText(runtime.vendor()),
        "runtime=" + requireText(runtime.version()),
        "os=" + requireText(runtime.operatingSystem()),
        "arch=" + requireText(runtime.architecture()),
        "osVersion=" + requireText(runtime.osVersion()),
        "javacClassSha256=" + sha256(compilerClass),
        "compilerImageSha256=" + ArtifactFileDigest.sha256(compilerImage),
        "platformImageSha256=" + ArtifactFileDigest.sha256(platformImage),
        "releaseApiImageSha256=" + ArtifactFileDigest.sha256(releaseApiImage));
  }

  /* default */ static boolean matchesSupportedImage(final String identity) {
    return identity != null
        && identity.contains("feature=" + SUPPORTED_FEATURE + ";")
        && identity.contains("module=" + COMPILER_MODULE + ";")
        && identity.contains("vendor=" + SUPPORTED_VENDOR + ";")
        && identity.contains("runtime=" + SUPPORTED_RUNTIME + ";")
        && identity.contains("javacClassSha256=" + SUPPORTED_JAVAC_CLASS_SHA256 + ";")
        && identity.contains("compilerImageSha256=" + SUPPORTED_COMPILER_IMAGE_SHA256 + ";")
        && identity.contains("platformImageSha256=" + SUPPORTED_PLATFORM_IMAGE_SHA256 + ";")
        && identity.contains("releaseApiImageSha256=" + SUPPORTED_RELEASE_API_SHA256);
  }

  /* default */ static Resolution requireSupportedIdentity(final String identity) {
    return matchesSupportedImage(identity)
        ? Resolution.supported(identity)
        : Resolution.unavailable(
            "Loaded JDK21 compiler/platform bytes are outside the supported pin");
  }

  private static byte[] compilerClassBytes(final JavaCompiler compiler) throws IOException {
    if (compiler == null) {
      throw new IOException("JDK 21 javac is unavailable");
    }
    final String classResource = "/" + compiler.getClass().getName().replace('.', '/') + ".class";
    try (InputStream input = compiler.getClass().getResourceAsStream(classResource)) {
      if (input == null) {
        throw new IOException("Loaded javac implementation bytes are unavailable");
      }
      return input.readAllBytes();
    }
  }

  private static void requireRegularFile(final Path path, final String label) throws IOException {
    if (!Files.isRegularFile(path)) {
      throw new IOException(label + " is unavailable: " + path);
    }
  }

  private static String requireText(final String value) throws IOException {
    if (value == null || value.isBlank()) {
      throw new IOException("JDK runtime identity metadata is incomplete");
    }
    return value;
  }

  private static String sha256(final byte[] bytes) {
    try {
      return HexFormat.of()
          .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /* default */ record Resolution(Optional<String> identity, Optional<String> refusal) {
    Resolution {
      if (identity.isPresent() == refusal.isPresent()) {
        throw new IllegalArgumentException("Exactly one source JDK identity outcome is required");
      }
    }

    /* default */ static Resolution supported(final String identity) {
      return new Resolution(Optional.of(identity), Optional.empty());
    }

    /* default */ static Resolution unavailable(final String refusal) {
      return new Resolution(
          Optional.empty(),
          Optional.of(
              refusal == null || refusal.isBlank()
                  ? "JDK compiler/platform identity is unavailable"
                  : refusal));
    }
  }

  /* default */ record RuntimeMetadata(
      String vendor,
      String version,
      String operatingSystem,
      String architecture,
      String osVersion) {}
}
