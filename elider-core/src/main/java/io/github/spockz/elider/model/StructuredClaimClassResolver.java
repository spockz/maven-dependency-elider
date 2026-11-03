/* WHY: Maps CNA source-file claims to exact class families using JarSourceFileIndex. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Derives proof class families from current file claims using JarSourceFileIndex. */
final class StructuredClaimClassResolver {
  private StructuredClaimClassResolver() {}

  /* default */ static Result derive(
      final CveAffectedEntryContext entry,
      final JarSourceFileIndex sourceIndex,
      final Path originalJar,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    final Set<String> selectedClasses = new HashSet<>();
    final List<StructuredProofProvenance.ClaimAttribution> attributions = new ArrayList<>();

    for (final String claim : entry.programFiles().stream().sorted().toList()) {
      if (!SourceClaimPathMatcher.isSupportedJavaSourceClaim(claim)) {
        continue;
      }
      final String sourceBasename = SourceClaimPathMatcher.basename(claim);
      final List<JarSourceFileIndex.ClassSourceFile> matchedClassFiles = new ArrayList<>();
      for (final JarSourceFileIndex.ClassSourceFile classFile : sourceIndex.classFiles()) {
        if (matchesClaim(classFile, claim, sourceBasename)) {
          matchedClassFiles.add(classFile);
        }
      }
      if (matchedClassFiles.isEmpty()) {
        throw new IOException(
            "A current CNA source-file claim has no exact archive match: " + claim);
      }
      final List<StructuredProofProvenance.ClassEntry> emittedClasses =
          readClassEntries(matchedClassFiles, originalJar);
      for (final JarSourceFileIndex.ClassSourceFile cf : matchedClassFiles) {
        selectedClasses.add(className(cf.physicalJarEntry()));
      }
      attributions.add(
          new StructuredProofProvenance.ClaimAttribution(
              StructuredProofProvenance.ClaimType.FILE, claim, claim, null, emittedClasses));
    }

    for (final String routine : entry.programRoutines().stream().sorted().toList()) {
      final List<JarSourceFileIndex.ClassSourceFile> owners = new ArrayList<>();
      for (final JarSourceFileIndex.ClassSourceFile classFile : sourceIndex.classFiles()) {
        if (classFile.declaredMethods().contains(routine)) {
          owners.add(classFile);
        }
      }
      if (owners.size() != 1) {
        throw new IOException("A current CNA routine claim has no unique owner: " + routine);
      }
      final JarSourceFileIndex.ClassSourceFile owner = owners.getFirst();
      final String ownerClassName = className(owner.physicalJarEntry());
      final String ownerClassPrefix = ownerClassName + "$";
      final List<JarSourceFileIndex.ClassSourceFile> familyClassFiles = new ArrayList<>();
      for (final JarSourceFileIndex.ClassSourceFile classFile : sourceIndex.classFiles()) {
        final String name = className(classFile.physicalJarEntry());
        if (name.equals(ownerClassName) || name.startsWith(ownerClassPrefix)) {
          familyClassFiles.add(classFile);
          selectedClasses.add(name);
        }
      }
      final List<StructuredProofProvenance.ClassEntry> emittedClasses =
          readClassEntries(familyClassFiles, originalJar);
      final String sourceEntry =
          owner.sourceFile() != null ? owner.sourceFile() : owner.physicalJarEntry();
      attributions.add(
          new StructuredProofProvenance.ClaimAttribution(
              StructuredProofProvenance.ClaimType.ROUTINE,
              routine,
              sourceEntry,
              ownerClassName,
              emittedClasses));
    }

    if (selectedClasses.isEmpty()) {
      throw new IOException("Current CNA claims identify no matched class family");
    }
    return new Result(selectedClasses, attributions);
  }

  private static boolean matchesClaim(
      final JarSourceFileIndex.ClassSourceFile classFile,
      final String claim,
      final String sourceBasename) {
    if (classFile.sourceFile() == null || !classFile.sourceFile().equals(sourceBasename)) {
      return false;
    }
    final String entry = classFile.classEntry();
    final String classPackage = SourceClaimPathMatcher.classPackage(entry);
    return !classPackage.isBlank() && SourceClaimPathMatcher.hasPackageSuffix(claim, classPackage);
  }

  private static List<StructuredProofProvenance.ClassEntry> readClassEntries(
      final List<JarSourceFileIndex.ClassSourceFile> matched, final Path originalJar)
      throws IOException {
    final List<StructuredProofProvenance.ClassEntry> entries = new ArrayList<>();
    try (ZipFile zip = new ZipFile(originalJar.toFile())) {
      for (final JarSourceFileIndex.ClassSourceFile cf : matched) {
        final ZipEntry zipEntry = zip.getEntry(cf.physicalJarEntry());
        if (zipEntry == null) {
          throw new IOException("Class entry not found in archive: " + cf.physicalJarEntry());
        }
        final byte[] bytes = zip.getInputStream(zipEntry).readAllBytes();
        final String sha256 = sha256Hex(bytes);
        entries.add(new StructuredProofProvenance.ClassEntry(cf.physicalJarEntry(), sha256));
      }
    }
    entries.sort(Comparator.comparing(StructuredProofProvenance.ClassEntry::path));
    return List.copyOf(entries);
  }

  private static String sha256Hex(final byte[] bytes) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(bytes));
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String className(final String path) throws IOException {
    if (!path.endsWith(".class") || path.startsWith("/") || path.contains("..")) {
      throw new IOException("Class inventory contains an invalid physical entry: " + path);
    }
    return path.substring(0, path.length() - ".class".length()).replace('/', '.');
  }

  /** Immutable result of mapping current source claims to outputs. */
  /* default */ record Result(
      Set<String> classNames, List<StructuredProofProvenance.ClaimAttribution> attributions) {
    Result {
      classNames = Set.copyOf(classNames);
      attributions = List.copyOf(attributions);
    }
  }
}
