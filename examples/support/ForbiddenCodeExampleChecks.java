// WHY: Verifies persisted policy, artifact bytes and VEX from the two benign ADR-0015 examples.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public final class ForbiddenCodeExampleChecks {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String COMPRESS_CVE = "CVE-2018-11771";
  private static final String RUNTIME_CVE = "CVE-2026-114938";
  private static final String ZIP_PACKAGE = "org/apache/commons/compress/archivers/zip/";
  private static final String STREAM_ENTRY = ZIP_PACKAGE + "ZipArchiveInputStream.class";
  private static final String DESCRIPTOR = "([BII)I";

  private ForbiddenCodeExampleChecks() {}

  public static void main(final String[] args) throws IOException {
    final Path scenario = Path.of(args[0]);
    final String expectedPrediction = args[1];
    final String expected = args[2];
    final String version = args[3];
    final boolean enforcePrediction = Boolean.parseBoolean(args[4]);
    final boolean enforceApplication = Boolean.parseBoolean(args[5]);
    final int target = args.length == 7 ? Integer.parseInt(args[6]) : Runtime.version().feature();
    final Path build = scenario.resolve("build");
    final JsonNode prediction = read(build.resolve("dependency-elider-analysis-report.json"));
    final JsonNode application = read(build.resolve("dependency-elider-report.json"));
    final boolean invokesDecoder = scenario.getFileName().toString().startsWith("decode");
    verifyRuntime(prediction, "PREDICTED", enforcePrediction, invokesDecoder, target);
    verifyRuntime(application, "OBSERVED", enforceApplication, invokesDecoder, target);
    verifyRule(prediction, expectedPrediction, version, "PREDICTED", enforcePrediction);
    final JsonNode observed =
        verifyRule(application, expected, version, "OBSERVED", enforceApplication);

    final Path original = originalArchive(scenario, version);
    require(declaresRead(original), "Original Commons Compress must declare " + DESCRIPTOR);
    verifyDigest(build.resolve("baseline-sbom.cdx.json"), version, HexDigest.sha256(original));
    final Path effective =
        observed.path("provider").isTextual()
            ? Path.of(observed.path("provider").asText())
            : original;
    final String sha256 = HexDigest.sha256(effective);
    verifyInventory(build, effective, version, sha256);

    if ("PASS".equals(expected)) {
      require(!Files.isSameFile(original, effective), "Pass must use the trimmed artifact");
      require(!hasEntry(effective, STREAM_ENTRY), "Trimmed archive still contains " + STREAM_ENTRY);
      verifyVex(build, application, version, sha256);
    } else {
      require(declaresRead(effective), "Effective archive must still declare " + DESCRIPTOR);
      require(
          !Files.exists(build.resolve("dependency-elider.openvex.json")),
          "A retained or out-of-scope declaration cannot create an omission VEX");
    }
    if ("untrimmed".equals(scenario.getFileName().toString())) {
      require(Files.isSameFile(original, effective), "Untrimmed assessment must use the input JAR");
    }
  }

  private static void verifyRuntime(
      final JsonNode snapshot,
      final String mode,
      final boolean enforced,
      final boolean directCall,
      final int target)
      throws IOException {
    final JsonNode runtime =
        single(snapshot.path("forbiddenCodeAssessments"), "cveId", RUNTIME_CVE);
    final boolean hasRuntimeImage = target == Runtime.version().feature();
    require(
        (directCall ? "VIOLATION" : "UNKNOWN").equals(runtime.path("status").asText())
            && "JAVA_RUNTIME".equals(runtime.path("componentKind").asText())
            && "java.util.Base64.Decoder#decode(byte[])".equals(runtime.path("symbol").asText())
            && (hasRuntimeImage ? "APPLICABLE" : "UNKNOWN")
                .equals(runtime.path("versionApplicability").asText())
            && "(,)".equals(runtime.path("versionScope").asText())
            && mode.equals(runtime.path("mode").asText())
            && enforced == runtime.path("enforcementEnabled").asBoolean()
            && !runtime.path("assertsAffected").asBoolean()
            && runtime.path("targetRelease").asInt() == target,
        "Runtime observation must include its actual identity and scope: " + runtime);
    if (hasRuntimeImage) {
      require(
          Runtime.version().toString().equals(runtime.path("componentVersion").asText())
              && !runtime.path("componentIdentity").asText().isBlank(),
          "Runtime identity must describe the inspected image: " + runtime);
    } else {
      require(
          runtime.path("componentVersion").isNull()
              && runtime.path("componentIdentity").isNull()
              && runtime.path("reason").asText().contains("No inspected Java runtime"),
          "Runtime identity must be unknown when the image is unavailable: " + runtime);
    }
    if (directCall) {
      final JsonNode match =
          single(
              runtime.path("matches"),
              "entry",
              "io/github/spockz/example/forbidden/DecodeApplication.class");
      require(
          "DIRECT_RUNTIME_CALL".equals(runtime.path("evidenceKind").asText())
              && "java.util.Base64$Decoder".equals(match.path("resolvedOwner").asText())
              && match.path("descriptors").size() == 1
              && "([B)[B".equals(match.path("descriptors").get(0).asText()),
          "Direct-call violation must identify the call site and overload: " + runtime);
    } else {
      final String evidence = hasRuntimeImage ? "RUNTIME_REACHABILITY" : "INCOMPLETE_SCOPE";
      require(
          evidence.equals(runtime.path("evidenceKind").asText())
              && !runtime.path("complete").asBoolean(),
          "Absent direct call leaves runtime reachability unknown: " + runtime);
    }
  }

  private static JsonNode verifyRule(
      final JsonNode snapshot,
      final String status,
      final String version,
      final String mode,
      final boolean enforced)
      throws IOException {
    final JsonNode rule = single(snapshot.path("forbiddenCodeAssessments"), "cveId", COMPRESS_CVE);
    require(
        status.equals(rule.path("status").asText())
            && mode.equals(rule.path("mode").asText())
            && enforced == rule.path("enforcementEnabled").asBoolean()
            && rule.path("assertsAffected").asBoolean()
            && "MAVEN_ARTIFACT".equals(rule.path("componentKind").asText())
            && "org.apache.commons:commons-compress:jar"
                .equals(rule.path("componentIdentity").asText())
            && version.equals(rule.path("componentVersion").asText())
            && "[1.7,1.18)".equals(rule.path("versionScope").asText())
            && ("1.18".equals(version) ? "NOT_APPLICABLE" : "APPLICABLE")
                .equals(rule.path("versionApplicability").asText())
            && "org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int)"
                .equals(rule.path("symbol").asText()),
        "Unexpected Commons Compress policy observation: " + rule);
    if ("VIOLATION".equals(status)) {
      final JsonNode match = single(rule.path("matches"), "entry", STREAM_ENTRY);
      require(
          match.path("descriptors").size() == 1
              && DESCRIPTOR.equals(match.path("descriptors").get(0).asText()),
          "A violation must identify the exact physical overload: " + match);
    }
    return rule;
  }

  private static Path originalArchive(final Path scenario, final String version)
      throws IOException {
    final String classpath = Files.readString(scenario.resolve("classpath")).strip();
    return Arrays.stream(classpath.split(Pattern.quote(java.io.File.pathSeparator)))
        .map(Path::of)
        .filter(
            path -> path.getFileName().toString().equals("commons-compress-" + version + ".jar"))
        .findFirst()
        .orElseThrow(() -> new IOException("No Commons Compress " + version + " in " + classpath));
  }

  private static void verifyInventory(
      final Path build, final Path effective, final String version, final String sha256)
      throws IOException {
    require(
        hasEntry(effective, ZIP_PACKAGE + "ZipArchiveEntry.class"),
        "The legitimate Commons Compress operation must remain available");
    verifyDigest(build.resolve("dependency-elider-sbom.cdx.json"), version, sha256);
  }

  private static void verifyDigest(final Path path, final String version, final String sha256)
      throws IOException {
    final JsonNode sbom = read(path);
    final JsonNode component = single(sbom.path("components"), "purl", purl(version));
    final JsonNode hash = single(component.path("hashes"), "alg", "SHA-256");
    require(sha256.equals(hash.path("content").asText()), path + " must bind the actual JAR bytes");
  }

  private static void verifyVex(
      final Path build, final JsonNode application, final String version, final String sha256)
      throws IOException {
    final JsonNode finding =
        single(application.path("genericFindings"), "vulnerabilityId", COMPRESS_CVE);
    require(
        "DECLARED_CODE_ABSENT".equals(finding.path("outcome").asText())
            && "AFFECTED".equals(finding.path("applicability").asText()),
        "Omission proof did not authorize VEX: " + finding.path("detail").asText());
    final JsonNode statements =
        read(build.resolve("dependency-elider.openvex.json")).path("statements");
    require(statements.size() == 1, "Only the verified dependency omission may create VEX");
    final JsonNode statement = statements.get(0);
    require(
        COMPRESS_CVE.equals(statement.path("vulnerability").path("name").asText())
            && "not_affected".equals(statement.path("status").asText())
            && "vulnerable_code_not_present".equals(statement.path("justification").asText()),
        "Wrong VEX finding: " + statement);
    final JsonNode component =
        single(statement.path("products").path(0).path("subcomponents"), "@id", purl(version));
    require(
        sha256.equals(component.path("hashes").path("sha-256").asText()),
        "VEX must apply to the verified trimmed artifact bytes");
  }

  private static String purl(final String version) {
    return "pkg:maven/org.apache.commons/commons-compress@" + version;
  }

  private static JsonNode read(final Path path) throws IOException {
    return JSON.readTree(path.toFile());
  }

  private static JsonNode single(final JsonNode rows, final String field, final String expected)
      throws IOException {
    final List<JsonNode> matches =
        StreamSupport.stream(rows.spliterator(), false)
            .filter(row -> expected.equals(row.path(field).asText()))
            .toList();
    require(matches.size() == 1, "Expected one " + field + "=" + expected + " in " + rows);
    return matches.getFirst();
  }

  private static boolean hasEntry(final Path path, final String entry) throws IOException {
    try (JarFile jar = new JarFile(path.toFile())) {
      return jar.getJarEntry(entry) != null;
    }
  }

  private static boolean declaresRead(final Path path) throws IOException {
    try (JarFile jar = new JarFile(path.toFile())) {
      final var entry = jar.getJarEntry(STREAM_ENTRY);
      if (entry == null) {
        return false;
      }
      final boolean[] found = {false};
      try (var input = jar.getInputStream(entry)) {
        final ClassReader reader = new ClassReader(input);
        reader.accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(
                  final int access,
                  final String name,
                  final String descriptor,
                  final String signature,
                  final String[] exceptions) {
                found[0] |=
                    (access & Opcodes.ACC_PUBLIC) != 0
                        && "read".equals(name)
                        && DESCRIPTOR.equals(descriptor);
                return null;
              }
            },
            ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
      }
      return found[0];
    }
  }

  private static void require(final boolean condition, final String message) throws IOException {
    if (!condition) {
      throw new IOException(message);
    }
  }
}
