/* WHY: Verifies exact Maven artifact binding for source CNA product claims. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests PURL and collection identity against complete Maven artifact coordinates. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class MavenPackageIdentityTest {
  /** Maven group used in exact package identity examples. */
  private static final String GROUP_ID = "org.example";

  /** Maven artifact used in exact package identity examples. */
  private static final String ARTIFACT_ID = "library";

  /** Concrete version used in exact package identity examples. */
  private static final String VERSION = "1.0";

  /** Nonmatching version used to prove version-specific PURL binding. */
  private static final String TEST_VERSION = "1.1";

  /** Maven artifact type for the classifier-specific fixture. */
  private static final String TEST_JAR_TYPE = "test-jar";

  /** Classifier for the test-jar fixture. */
  private static final String TESTS_CLASSIFIER = "tests";

  /** Maven scope for coordinates in this fixture. */
  private static final String TEST_SCOPE = "test";

  /** Exact Maven group and artifact encoded by the collection identity. */
  private static final String PACKAGE_NAME = "org.example:library";

  /** The recognized source collection used by Maven Central CNA entries. */
  private static final String COLLECTION = "https://repo.maven.apache.org/maven2";

  @Test
  void purlDefaultsAndSuppliedGavceFieldsAreExact() {
    final MavenPackageIdentity versioned =
        MavenPackageIdentity.parse(
                "pkg:maven/org.example/library@1.0?type=test-jar&classifier=tests")
            .orElseThrow();
    final MavenPackageIdentity defaults =
        MavenPackageIdentity.parse("pkg:maven/org.example/library").orElseThrow();
    final boolean exactVariant =
        versioned.matches(
            new ArtifactCoordinate(
                GROUP_ID, ARTIFACT_ID, VERSION, TEST_JAR_TYPE, TESTS_CLASSIFIER, TEST_SCOPE));
    final boolean wrongType =
        versioned.matches(
            new ArtifactCoordinate(
                GROUP_ID, ARTIFACT_ID, VERSION, "jar", TESTS_CLASSIFIER, TEST_SCOPE));
    final boolean wrongVersion =
        versioned.matches(
            new ArtifactCoordinate(
                GROUP_ID, ARTIFACT_ID, TEST_VERSION, TEST_JAR_TYPE, TESTS_CLASSIFIER, TEST_SCOPE));
    final boolean defaultJar =
        defaults.matches(ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, VERSION));
    final boolean unsupportedRepository =
        MavenPackageIdentity.parse(
                "pkg:maven/org.example/library?repository_url=" + "https%3A%2F%2Frepo.example.test")
            .isPresent();

    assertAll(
        "PURL defaults apply only when omitted and supplied identity fields must agree",
        () -> assertTrue(exactVariant, "the complete PURL GAVCE must match"),
        () -> assertFalse(wrongType, "a PURL test-jar type cannot match a jar coordinate"),
        () -> assertFalse(wrongVersion, "a supplied PURL version must match exactly"),
        () -> assertTrue(defaultJar, "an omitted PURL type defaults to jar"),
        () ->
            assertFalse(
                unsupportedRepository, "unknown PURL qualifiers cannot establish identity"));
  }

  @Test
  void collectionIdentityRequiresRecognizedRepositoryAndConsistentPackage() {
    final ArtifactCoordinate jar = ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, VERSION);
    final ArtifactCoordinate tests =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, "jar", TESTS_CLASSIFIER, TEST_SCOPE);
    final CveAffectedEntryContext collection = entry(null, COLLECTION, PACKAGE_NAME);
    final CveAffectedEntryContext mismatch = entry(null, COLLECTION, "org.other:library");
    final CveAffectedEntryContext unsupportedRepository =
        entry(null, "https://repo.example.test/maven2", PACKAGE_NAME);
    final CveAffectedEntryContext nonDefaultPort =
        entry(null, "https://repo.maven.apache.org:8443/maven2", PACKAGE_NAME);
    final boolean collectionMatchesJar = MavenPackageIdentity.matchesCnaArtifact(collection, jar);
    final boolean collectionMatchesTestArtifact =
        MavenPackageIdentity.matchesCnaArtifact(collection, tests);
    final boolean wrongPackageRejected =
        MavenPackageIdentity.matchesCnaPackage(mismatch, GROUP_ID, ARTIFACT_ID);
    final boolean unsupportedCollectionRejected =
        MavenPackageIdentity.matchesCnaPackage(unsupportedRepository, GROUP_ID, ARTIFACT_ID);
    final boolean nonDefaultPortRejected =
        MavenPackageIdentity.matchesCnaPackage(nonDefaultPort, GROUP_ID, ARTIFACT_ID);

    assertAll(
        "collection packageName is an identity only for the recognized Maven collection",
        () ->
            assertTrue(collectionMatchesJar, "the recognized collection and packageName bind jar"),
        () ->
            assertFalse(
                collectionMatchesTestArtifact, "collection identity defaults to unclassified jar"),
        () -> assertFalse(wrongPackageRejected, "collection packageName must be exact"),
        () ->
            assertFalse(unsupportedCollectionRejected, "unknown collections cannot bind a package"),
        () -> assertFalse(nonDefaultPortRejected, "noncanonical repository ports are unsupported"));
  }

  @Test
  void packageUrlAndCollectionIdentityMustAgree() {
    final CveAffectedEntryContext contradictory =
        entry("pkg:maven/org.example/other", COLLECTION, PACKAGE_NAME);
    final boolean packageContradictionRejected =
        MavenPackageIdentity.matchesCnaPackage(contradictory, GROUP_ID, ARTIFACT_ID);
    final boolean artifactContradictionRejected =
        MavenPackageIdentity.matchesCnaArtifact(
            contradictory, ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, VERSION));

    assertAll(
        () -> assertFalse(packageContradictionRejected, "the two package identities conflict"),
        () ->
            assertFalse(
                artifactContradictionRejected, "contradictory identity cannot bind an artifact"));
  }

  @Test
  void purlArtifactVariantAndVersionMustMatchTheAnalyzedCoordinate() {
    final CveAffectedEntryContext variant =
        entry("pkg:maven/org.example/library@1.0?type=test-jar&classifier=tests", null, null);
    final ArtifactCoordinate exact =
        new ArtifactCoordinate(
            GROUP_ID, ARTIFACT_ID, VERSION, TEST_JAR_TYPE, TESTS_CLASSIFIER, TEST_SCOPE);
    final ArtifactCoordinate wrongVersion =
        new ArtifactCoordinate(
            GROUP_ID, ARTIFACT_ID, TEST_VERSION, TEST_JAR_TYPE, TESTS_CLASSIFIER, TEST_SCOPE);
    final ArtifactCoordinate wrongClassifier =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, TEST_JAR_TYPE, "", TEST_SCOPE);
    final boolean exactArtifact = MavenPackageIdentity.matchesCnaArtifact(variant, exact);
    final boolean wrongArtifactVersion =
        MavenPackageIdentity.matchesCnaArtifact(variant, wrongVersion);
    final boolean wrongArtifactClassifier =
        MavenPackageIdentity.matchesCnaArtifact(variant, wrongClassifier);

    assertAll(
        "a PURL's optional concrete GAVCE fields bind the source entry to one artifact",
        () -> assertTrue(exactArtifact, "the PURL's exact version and variant match"),
        () -> assertFalse(wrongArtifactVersion, "the PURL version differs"),
        () -> assertFalse(wrongArtifactClassifier, "the PURL classifier differs"));
  }

  @Test
  void osvPackageProjectionCannotInventCoordinateVariantOrVersion() {
    assertAll(
        "OSV package source identity contains only group and artifact",
        () ->
            assertThatThrownBy(
                    () ->
                        new OsvAffectedPackage(
                            "Maven",
                            PACKAGE_NAME,
                            new ArtifactCoordinate(
                                GROUP_ID, ARTIFACT_ID, VERSION, "jar", "", "compile"),
                            List.of(VERSION),
                            List.of()))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        new OsvAffectedPackage(
                            "Maven",
                            PACKAGE_NAME,
                            new ArtifactCoordinate(
                                GROUP_ID, ARTIFACT_ID, null, "war", "", "compile"),
                            List.of(VERSION),
                            List.of()))
                .isInstanceOf(IllegalArgumentException.class));
  }

  private static CveAffectedEntryContext entry(
      final String packageUrl, final String collectionUrl, final String packageName) {
    return new CveAffectedEntryContext(
        "containers.cna.affected[0]",
        new CveSourceRecordMetadata(
            true, true, true, "CVE-2026-12345", true, "PUBLISHED", "a".repeat(64)),
        "Example",
        ARTIFACT_ID,
        packageUrl,
        collectionUrl,
        packageName,
        null,
        List.of(),
        Set.of(),
        Set.of());
  }
}
