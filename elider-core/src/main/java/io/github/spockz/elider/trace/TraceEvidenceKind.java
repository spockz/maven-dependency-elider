/* WHY: Preserves the semantic limits of each explicit runtime-evidence format. */

package io.github.spockz.elider.trace;

/** Distinguishes runtime observations from probe and configuration inputs. */
public enum TraceEvidenceKind {
  CLASS_LOAD_LOG,
  CDS_CLASS_LIST,
  JFR_CLASS_LOAD,
  JACOCO_EXECUTION,
  GRAAL_CONFIGURATION,
  UNCLASSIFIED
}
