<!-- WHY: Documents the usable Maven goal and the lifecycle safety boundary for plugin consumers. -->
# Maven Plugin Usage

Maven Dependency Elider provides four primary goals:

* `analyze`: Dry-run that identifies removable dependencies and estimates size savings without changing dependency artifacts, classpaths, or packages. It may write the configured class-usage report.
* `elide`: Active build-time goal that prunes unneeded JARs and trims unreferenced classes during the `INITIALIZE` phase.
* `report`: Displays the persisted elision snapshot and mediated dependency graph from the last successful build.
* `update-cve-index`: Refreshes local vulnerability intelligence from OSV and CVEList v5.

For common questions, see the [User FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/faq.md) and [Contributor Decisions and FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md).

---

## 1. Quick Installation

Install the plugin and core engine into your local Maven repository:

```sh
./mvnw -pl dependency-elider-maven-plugin -am install
```

---

## 2. Capturing Runtime Telemetry

Elision requires evidence of classes loaded during execution. Capture runtime telemetry using any supported JVM sensor:

| Telemetry Format | File Extension | JVM Flag or Tool Command |
| :--- | :--- | :--- |
| **Class-load logs** | `.log`, `.txt` | `-Xlog:class+load=info:file=target/classes.log` |
| **CDS Class List** | `.lst` | `-XX:DumpLoadedClassList=target/classes.lst` |
| **JDK Flight Recorder** | `.jfr` | `-XX:StartFlightRecording=dumponexit=true,filename=target/recording.jfr` |
| **GraalVM Reflection** | `.json` | Native Image Tracing Agent (`-agentlib:native-image-agent=config-output-dir=...`) |
| **JaCoCo Execution** | `.exec` | JaCoCo Java Agent (`-javaagent:jacocoagent.jar=destfile=target/jacoco.exec`) |

### Telemetry Rules

* Pass one or more file paths as a comma-separated list via `-Delide.traceFiles`.
* Every specified file must exist, be readable, and use a supported format.
* The merged trace set must be non-empty and match at least one class in a resolved JAR dependency.
* Malformed traces or traces with no matching classes fail the goal.

---

## 3. Dry-Run Analysis (`analyze`)

Run `analyze` to inspect potential dependency drops and byte savings without altering Maven artifact views, resolver plans, or packaged outputs. The goal writes class-usage evidence to `elide.reportFile` (default `target/dependency-elider-class-usage.json`) and a summary to `elide.analysisSummaryFile` (default `target/dependency-elider-analysis-report.json`). The summary uses the same schema and renderer as the applied report, marks its mode `ANALYSIS`, and leaves unavailable output byte measurements unknown. The `report` goal can replay it using `-Delide.summaryFile=target/dependency-elider-analysis-report.json` without re-running analysis. The applied report remains separate.

Class-usage schema 1 includes a `dependencyPrediction` section with retained and predicted-elided coordinates, planned class removals marked `PLANNED_UNVERIFIED`, environment/inventory/operation fingerprints, and provenance (`CAPTURED_EFFECTIVE_RESOLVER` or `DETACHED_CURRENT_MODEL`). Detached provenance describes only that request-local resolution. A `PLANNED_CODE_ABSENT` finding means all attributed classes for a complete declared code group are planned for removal; it is not verified archive evidence, a scanner result, a CVE mitigation claim, or a VEX attestation. Prediction does not publish trim archives or output-manifest/generation state. MRJAR analysis may create temporary classpath projections in an operation-owned directory; that directory is removed when prediction completes or fails. Choose a path under `.scratch` if the class-usage report should not be kept with build artifacts:

With or without the core extension, `analyze` can predict exact `groupId:artifactId` bans for supported compile/runtime JARs. It uses either a detached current-model Resolver graph or the captured effective graph with a complete original-input audit. Schema-1 `dependencyPrediction.banPlan` classifies each request as matched (`FORCED_ABSENT_AFTER_RESOLUTION`), excluded before resolution (`EXCLUDED_BEFORE_RESOLUTION`), or unmatched (`UNMATCHED`); every prediction row has `applied=false`. Analysis fails if trace, source, bytecode, retained-resource/provider metadata, or graph closure requires a banned artifact. An unmatched request is not an absence proof. Analyze only predicts and never applies bans or changes Maven artifact views.

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

The repository's CVE example transcript includes its configured command, exit status, and captured analysis output. It uses the complete pinned [OSV Maven and CVE List snapshots](https://github.com/spockz/maven-dependency-elider/blob/main/scripts/fixtures/vulnerability-snapshots/README.md), stored with Git LFS. The results reflect those snapshots, not live coverage. `$PROJECT_ROOT` and `$TRANSCRIPT_EVIDENCE` stand for the repository and temporary trace directory created by `make update-transcripts`:

<!-- BEGIN:transcript:analyze-cve-unused-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-cve-unused-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=$TRANSCRIPT_EVIDENCE/example-cve-unused-app.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.trimSkipArtifacts=org.springframework:spring-context:6.2.7:jar:,org.springframework:spring-beans:6.2.7:jar:,org.springframework:spring-aop:6.2.7:jar:,org.springframework:spring-expression:6.2.7:jar:,org.springframework:spring-core:6.2.7:jar:,org.springframework:spring-jcl:6.2.7:jar:,io.micrometer:micrometer-observation:1.15.0:jar:,io.micrometer:micrometer-commons:1.15.0:jar: \
  -Delide.cveCacheDirectory=$TRANSCRIPT_EVIDENCE/vulnerability-cache \
  -Delide.reportFile=$PROJECT_ROOT/.scratch/transcript-analysis/analyze-cve-unused-app-class-usage.json
Process exit status: 0
[INFO]
[INFO] --------------< io.github.spockz:example-cve-unused-app >---------------
[INFO] Building Example: Graph-Backed CVE Dependency Analysis 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:analyze (default-cli) @ example-cve-unused-app ---
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: analysis prediction at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts that would be dropped: 0 / 25 (original JAR file bytes: 0 B)
[INFO] Program classes that would be removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Planned bans: none
[INFO] Program classes that would be pruned from retained JARs: 330 (uncompressed omitted .class payload bytes: unknown; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile): 20 classes, unknown
[INFO]     Would remove classes: [com.fasterxml.jackson.core.JsonpCharacterEscapes, com.fasterxml.jackson.core.async.package-info, com.fasterxml.jackson.core.base.package-info, com.fasterxml.jackson.core.exc.package-info, com.fasterxml.jackson.core.filter.FilteringGeneratorDelegate, com.fasterxml.jackson.core.format.DataFormatDetector, com.fasterxml.jackson.core.format.package-info, com.fasterxml.jackson.core.internal.shaded.fdp.v2_19_0.package-info, com.fasterxml.jackson.core.json.async.package-info, com.fasterxml.jackson.core.json.package-info, com.fasterxml.jackson.core.package-info, com.fasterxml.jackson.core.sym.Name, com.fasterxml.jackson.core.sym.Name1, com.fasterxml.jackson.core.sym.Name2, com.fasterxml.jackson.core.sym.Name3, com.fasterxml.jackson.core.sym.NameN, com.fasterxml.jackson.core.sym.package-info, com.fasterxml.jackson.core.type.package-info, com.fasterxml.jackson.core.util.JsonGeneratorDelegate, com.fasterxml.jackson.core.util.package-info]
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, unknown
[INFO]     Would remove classes: [com.fasterxml.jackson.databind.EnumNamingStrategies, com.fasterxml.jackson.databind.EnumNamingStrategies$CamelCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies, com.fasterxml.jackson.databind.PropertyNamingStrategies$KebabCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$LowerCamelCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$LowerCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$LowerDotCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$NamingBase, com.fasterxml.jackson.databind.PropertyNamingStrategies$SnakeCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$UpperCamelCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$UpperSnakeCaseStrategy, com.fasterxml.jackson.databind.annotation.package-info, com.fasterxml.jackson.databind.cfg.package-info, com.fasterxml.jackson.databind.deser.impl.package-info, com.fasterxml.jackson.databind.deser.package-info, com.fasterxml.jackson.databind.deser.std.DelegatingDeserializer, com.fasterxml.jackson.databind.deser.std.StdNodeBasedDeserializer, com.fasterxml.jackson.databind.deser.std.package-info, com.fasterxml.jackson.databind.ext.CoreXMLDeserializers, com.fasterxml.jackson.databind.ext.CoreXMLDeserializers$Std, com.fasterxml.jackson.databind.ext.CoreXMLSerializers, com.fasterxml.jackson.databind.ext.CoreXMLSerializers$XMLGregorianCalendarSerializer, com.fasterxml.jackson.databind.ext.DOMDeserializer, com.fasterxml.jackson.databind.ext.DOMDeserializer$DocumentDeserializer, com.fasterxml.jackson.databind.ext.DOMDeserializer$NodeDeserializer, com.fasterxml.jackson.databind.ext.DOMSerializer, com.fasterxml.jackson.databind.ext.SqlBlobSerializer, com.fasterxml.jackson.databind.ext.package-info, com.fasterxml.jackson.databind.introspect.WithMember, com.fasterxml.jackson.databind.introspect.package-info, com.fasterxml.jackson.databind.jdk14.package-info, com.fasterxml.jackson.databind.jsonFormatVisitors.package-info, com.fasterxml.jackson.databind.jsonschema.package-info, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$1, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$2, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$3, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$4, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$5, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$6, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$Builder$7, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$NameMatcher, com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator$TypeMatcher, com.fasterxml.jackson.databind.jsontype.impl.package-info, com.fasterxml.jackson.databind.jsontype.package-info, com.fasterxml.jackson.databind.module.SimpleAbstractTypeResolver, com.fasterxml.jackson.databind.module.SimpleDeserializers, com.fasterxml.jackson.databind.module.SimpleKeyDeserializers, com.fasterxml.jackson.databind.module.SimpleModule, com.fasterxml.jackson.databind.module.SimpleSerializers, com.fasterxml.jackson.databind.module.SimpleValueInstantiators, com.fasterxml.jackson.databind.module.package-info, com.fasterxml.jackson.databind.node.package-info, com.fasterxml.jackson.databind.package-info, com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider, com.fasterxml.jackson.databind.ser.impl.package-info, com.fasterxml.jackson.databind.ser.package-info, com.fasterxml.jackson.databind.ser.std.NonTypedScalarSerializerBase, com.fasterxml.jackson.databind.ser.std.SqlDateSerializer, com.fasterxml.jackson.databind.ser.std.SqlTimeSerializer, com.fasterxml.jackson.databind.type.package-info, com.fasterxml.jackson.databind.util.ISO8601DateFormat, com.fasterxml.jackson.databind.util.ISO8601Utils, com.fasterxml.jackson.databind.util.JSONPObject, com.fasterxml.jackson.databind.util.JSONWrappedObject, com.fasterxml.jackson.databind.util.JacksonCollectors, com.fasterxml.jackson.databind.util.StdConverter, com.fasterxml.jackson.databind.util.internal.package-info, com.fasterxml.jackson.databind.util.package-info]
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, unknown
[INFO]     Would remove classes: [org.apache.commons.text.AlphabetConverter, org.apache.commons.text.Builder, org.apache.commons.text.CaseUtils, org.apache.commons.text.CharacterPredicate, org.apache.commons.text.CharacterPredicates, org.apache.commons.text.CharacterPredicates$1, org.apache.commons.text.CharacterPredicates$2, org.apache.commons.text.CharacterPredicates$3, org.apache.commons.text.CharacterPredicates$4, org.apache.commons.text.CharacterPredicates$5, org.apache.commons.text.CharacterPredicates$6, org.apache.commons.text.CharacterPredicates$7, org.apache.commons.text.CompositeFormat, org.apache.commons.text.ExtendedMessageFormat, org.apache.commons.text.FormatFactory, org.apache.commons.text.FormattableUtils, org.apache.commons.text.RandomStringGenerator, org.apache.commons.text.RandomStringGenerator$1, org.apache.commons.text.RandomStringGenerator$Builder, org.apache.commons.text.StrBuilder, org.apache.commons.text.StrBuilder$StrBuilderReader, org.apache.commons.text.StrBuilder$StrBuilderTokenizer, org.apache.commons.text.StrBuilder$StrBuilderWriter, org.apache.commons.text.StrLookup, org.apache.commons.text.StrLookup$1, org.apache.commons.text.StrLookup$MapStrLookup, org.apache.commons.text.StrLookup$ResourceBundleLookup, org.apache.commons.text.StrLookup$SystemPropertiesStrLookup, org.apache.commons.text.StrMatcher, org.apache.commons.text.StrMatcher$CharMatcher, org.apache.commons.text.StrMatcher$CharSetMatcher, org.apache.commons.text.StrMatcher$NoMatcher, org.apache.commons.text.StrMatcher$StringMatcher, org.apache.commons.text.StrMatcher$TrimMatcher, org.apache.commons.text.StrSubstitutor, org.apache.commons.text.StrTokenizer, org.apache.commons.text.StringEscapeUtils, org.apache.commons.text.StringEscapeUtils$1, org.apache.commons.text.StringEscapeUtils$Builder, org.apache.commons.text.StringEscapeUtils$XsiUnescaper, org.apache.commons.text.StringSubstitutor, org.apache.commons.text.StringSubstitutor$1, org.apache.commons.text.StringSubstitutor$Result, org.apache.commons.text.StringTokenizer, org.apache.commons.text.TextRandomProvider, org.apache.commons.text.TextStringBuilder, org.apache.commons.text.TextStringBuilder$TextStringBuilderReader, org.apache.commons.text.TextStringBuilder$TextStringBuilderTokenizer, org.apache.commons.text.TextStringBuilder$TextStringBuilderWriter, org.apache.commons.text.WordUtils, org.apache.commons.text.diff.CommandVisitor, org.apache.commons.text.diff.DeleteCommand, org.apache.commons.text.diff.EditCommand, org.apache.commons.text.diff.EditScript, org.apache.commons.text.diff.InsertCommand, org.apache.commons.text.diff.KeepCommand, org.apache.commons.text.diff.ReplacementsFinder, org.apache.commons.text.diff.ReplacementsHandler, org.apache.commons.text.diff.StringsComparator, org.apache.commons.text.diff.StringsComparator$Snake, org.apache.commons.text.io.StringSubstitutorReader, org.apache.commons.text.lookup.AbstractStringLookup, org.apache.commons.text.lookup.BiFunctionStringLookup, org.apache.commons.text.lookup.BiStringLookup, org.apache.commons.text.lookup.ConstantStringLookup, org.apache.commons.text.lookup.DateStringLookup, org.apache.commons.text.lookup.DefaultStringLookup, org.apache.commons.text.lookup.DnsStringLookup, org.apache.commons.text.lookup.FileStringLookup, org.apache.commons.text.lookup.FunctionStringLookup, org.apache.commons.text.lookup.IllegalArgumentExceptions, org.apache.commons.text.lookup.InetAddressKeys, org.apache.commons.text.lookup.InterpolatorStringLookup, org.apache.commons.text.lookup.JavaPlatformStringLookup, org.apache.commons.text.lookup.LocalHostStringLookup, org.apache.commons.text.lookup.PropertiesStringLookup, org.apache.commons.text.lookup.ResourceBundleStringLookup, org.apache.commons.text.lookup.ScriptStringLookup, org.apache.commons.text.lookup.StringLookup, org.apache.commons.text.lookup.StringLookupFactory, org.apache.commons.text.lookup.UrlDecoderStringLookup, org.apache.commons.text.lookup.UrlEncoderStringLookup, org.apache.commons.text.lookup.UrlStringLookup, org.apache.commons.text.lookup.XmlStringLookup, org.apache.commons.text.matcher.AbstractStringMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$AndStringMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$CharArrayMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$CharMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$CharSetMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$NoneMatcher, org.apache.commons.text.matcher.AbstractStringMatcher$TrimMatcher, org.apache.commons.text.matcher.StringMatcher, org.apache.commons.text.matcher.StringMatcherFactory, org.apache.commons.text.similarity.CosineDistance, org.apache.commons.text.similarity.CosineSimilarity, org.apache.commons.text.similarity.Counter, org.apache.commons.text.similarity.EditDistanceFrom, org.apache.commons.text.similarity.FuzzyScore, org.apache.commons.text.similarity.HammingDistance, org.apache.commons.text.similarity.IntersectionResult, org.apache.commons.text.similarity.IntersectionSimilarity, org.apache.commons.text.similarity.IntersectionSimilarity$1, org.apache.commons.text.similarity.IntersectionSimilarity$BagCount, org.apache.commons.text.similarity.IntersectionSimilarity$TinyBag, org.apache.commons.text.similarity.JaccardDistance, org.apache.commons.text.similarity.JaccardSimilarity, org.apache.commons.text.similarity.JaroWinklerDistance, org.apache.commons.text.similarity.JaroWinklerSimilarity, org.apache.commons.text.similarity.LevenshteinDetailedDistance, org.apache.commons.text.similarity.LevenshteinResults, org.apache.commons.text.similarity.LongestCommonSubsequence, org.apache.commons.text.similarity.LongestCommonSubsequenceDistance, org.apache.commons.text.similarity.RegexTokenizer, org.apache.commons.text.similarity.SimilarityScoreFrom, org.apache.commons.text.similarity.Tokenizer, org.apache.commons.text.translate.AggregateTranslator, org.apache.commons.text.translate.CharSequenceTranslator, org.apache.commons.text.translate.CodePointTranslator, org.apache.commons.text.translate.CsvTranslators, org.apache.commons.text.translate.CsvTranslators$CsvEscaper, org.apache.commons.text.translate.CsvTranslators$CsvUnescaper, org.apache.commons.text.translate.EntityArrays, org.apache.commons.text.translate.JavaUnicodeEscaper, org.apache.commons.text.translate.LookupTranslator, org.apache.commons.text.translate.NumericEntityEscaper, org.apache.commons.text.translate.NumericEntityUnescaper, org.apache.commons.text.translate.NumericEntityUnescaper$OPTION, org.apache.commons.text.translate.OctalUnescaper, org.apache.commons.text.translate.SinglePassTranslator, org.apache.commons.text.translate.UnicodeEscaper, org.apache.commons.text.translate.UnicodeUnescaper, org.apache.commons.text.translate.UnicodeUnpairedSurrogateRemover]
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, unknown
[INFO]     Would remove classes: [org.codehaus.commons.compiler.Sandbox, org.codehaus.commons.compiler.Sandbox$1, org.codehaus.commons.compiler.io.InputStreams, org.codehaus.commons.compiler.io.package-info, org.codehaus.commons.compiler.java8.java.util.function.package-info, org.codehaus.commons.compiler.java8.java.util.package-info, org.codehaus.commons.compiler.java8.java.util.stream.package-info, org.codehaus.commons.compiler.java9.java.lang.module.package-info, org.codehaus.commons.compiler.lang.ClassLoaders, org.codehaus.commons.compiler.lang.ClassLoaders$1, org.codehaus.commons.compiler.lang.ClassLoaders$2, org.codehaus.commons.compiler.lang.ClassLoaders$3, org.codehaus.commons.compiler.lang.ClassLoaders$3$1, org.codehaus.commons.compiler.lang.ClassLoaders$SubresourceGetter, org.codehaus.commons.compiler.lang.package-info, org.codehaus.commons.compiler.package-info, org.codehaus.commons.compiler.samples.ClassBodyDemo, org.codehaus.commons.compiler.samples.CompilerDemo, org.codehaus.commons.compiler.samples.DemoBase, org.codehaus.commons.compiler.samples.ExpressionDemo, org.codehaus.commons.compiler.samples.ScriptDemo, org.codehaus.commons.compiler.samples.ShippingCost, org.codehaus.commons.compiler.samples.package-info, org.codehaus.commons.compiler.util.Producer, org.codehaus.commons.compiler.util.ResourceFinderClassLoader, org.codehaus.commons.compiler.util.iterator.DirectoryIterator, org.codehaus.commons.compiler.util.iterator.DirectoryIterator$1, org.codehaus.commons.compiler.util.iterator.DirectoryIterator$1$State, org.codehaus.commons.compiler.util.iterator.DirectoryIterator$DirectoryNotListableException, org.codehaus.commons.compiler.util.iterator.MultiIterator, org.codehaus.commons.compiler.util.iterator.ProducerIterator, org.codehaus.commons.compiler.util.iterator.TraversingIterator, org.codehaus.commons.compiler.util.iterator.package-info, org.codehaus.commons.compiler.util.package-info, org.codehaus.commons.compiler.util.reflect.ApiLog, org.codehaus.commons.compiler.util.reflect.ApiLog$1, org.codehaus.commons.compiler.util.reflect.NoException, org.codehaus.commons.compiler.util.reflect.package-info, org.codehaus.commons.compiler.util.resource.MapResourceCreator, org.codehaus.commons.compiler.util.resource.MapResourceCreator$1, org.codehaus.commons.compiler.util.resource.MapResourceFinder, org.codehaus.commons.compiler.util.resource.MapResourceFinder$1, org.codehaus.commons.compiler.util.resource.MapResourceFinder$2, org.codehaus.commons.compiler.util.resource.ResourceFinders, org.codehaus.commons.compiler.util.resource.ResourceFinders$1, org.codehaus.commons.compiler.util.resource.ResourceFinders$2, org.codehaus.commons.compiler.util.resource.ResourceFinders$3, org.codehaus.commons.compiler.util.resource.ResourceFinders$4, org.codehaus.commons.compiler.util.resource.StringResource, org.codehaus.commons.compiler.util.resource.package-info, org.codehaus.commons.nullanalysis.NotNull]
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, unknown
[INFO]     Would remove classes: [org.codehaus.janino.AntCompilerAdapter, org.codehaus.janino.CachingJavaSourceClassLoader, org.codehaus.janino.Unparser, org.codehaus.janino.Unparser$1, org.codehaus.janino.Unparser$10, org.codehaus.janino.Unparser$11, org.codehaus.janino.Unparser$12, org.codehaus.janino.Unparser$13, org.codehaus.janino.Unparser$14, org.codehaus.janino.Unparser$15, org.codehaus.janino.Unparser$16, org.codehaus.janino.Unparser$17, org.codehaus.janino.Unparser$18, org.codehaus.janino.Unparser$2, org.codehaus.janino.Unparser$3, org.codehaus.janino.Unparser$4, org.codehaus.janino.Unparser$5, org.codehaus.janino.Unparser$6, org.codehaus.janino.Unparser$7, org.codehaus.janino.Unparser$8, org.codehaus.janino.Unparser$9, org.codehaus.janino.package-info, org.codehaus.janino.samples.DeclarationCounter, org.codehaus.janino.samples.package-info, org.codehaus.janino.tools.HprofScrubber, org.codehaus.janino.tools.HprofScrubber$1, org.codehaus.janino.tools.HprofScrubber$Sample, org.codehaus.janino.tools.HprofScrubber$Site, org.codehaus.janino.tools.package-info, org.codehaus.janino.util.AutoIndentWriter, org.codehaus.janino.util.DeepCopier, org.codehaus.janino.util.DeepCopier$1, org.codehaus.janino.util.DeepCopier$10, org.codehaus.janino.util.DeepCopier$11, org.codehaus.janino.util.DeepCopier$12, org.codehaus.janino.util.DeepCopier$13, org.codehaus.janino.util.DeepCopier$14, org.codehaus.janino.util.DeepCopier$15, org.codehaus.janino.util.DeepCopier$16, org.codehaus.janino.util.DeepCopier$17, org.codehaus.janino.util.DeepCopier$18, org.codehaus.janino.util.DeepCopier$2, org.codehaus.janino.util.DeepCopier$3, org.codehaus.janino.util.DeepCopier$4, org.codehaus.janino.util.DeepCopier$5, org.codehaus.janino.util.DeepCopier$6, org.codehaus.janino.util.DeepCopier$7, org.codehaus.janino.util.DeepCopier$8, org.codehaus.janino.util.DeepCopier$9, org.codehaus.janino.util.charstream.package-info, org.codehaus.janino.util.package-info, org.codehaus.janino.util.signature.package-info]
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, unknown
[INFO]     Would remove classes: [org.slf4j.LoggerFactoryFriend, org.slf4j.helpers.MarkerIgnoringBase, org.slf4j.helpers.Slf4jEnvUtil, org.slf4j.spi.LoggerFactoryBinder, org.slf4j.spi.MarkerFactoryBinder]
[INFO] Analysis only: no trim proof or published changes
[INFO] Vulnerability findings: 29
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2022-42889, GHSA-599f-7c49-w659]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: PLANNED_CODE_ABSENT; Analysis would remove declared code; the resulting archive has not been verified
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] RESOLVED; classes: [org.apache.commons.text.lookup.StringLookup]; reasons: []
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.apache.commons.text.lookup.StringLookup]
[INFO]     Overridden fields: [code, intent]
[INFO]     Sources: [OSV, POM]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41249 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41249, GHSA-jmp9-x22r-554x]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-110879 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/DatabindContext.java] RESOLVED; classes: [com.fasterxml.jackson.databind.DatabindContext]; reasons: []
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/impl/StdTypeResolverBuilder.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder, com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder$1]; reasons: []
[INFO]     Declared code: [DatabindContext._resolveAndValidateGeneric] RESOLVED; classes: [com.fasterxml.jackson.databind.DatabindContext]; reasons: []
[INFO]     Declared code: [DatabindContext._validateTypeParameter] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Declared code: [DefaultBaseTypeLimitingValidator] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Declared code: [StdTypeResolverBuilder] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-1225 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-1225, GHSA-qqpg-mvqg-649v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-18401 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-18401, GHSA-72hv-8253-57qq]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._valueComplete] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-19032 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-19032, GHSA-wjgm-6hv5-3cvf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/ext/NioPathDeserializer.java] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.NioPathDeserializer]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.ext.NioPathDeserializer.deserialize] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.NioPathDeserializer]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-41848 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41848, GHSA-659m-px2c-25wj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41850 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41850, GHSA-r5w3-xv2f-j59q]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41851 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41851, GHSA-wxpp-56q6-5pcg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41852 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41852, GHSA-9f52-rjqv-25qv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54512 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54512, GHSA-j3rv-43j4-c7qm]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54513 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54513, GHSA-rmj7-2vxq-3g9f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54514 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54514, GHSA-hgj6-7826-r7m5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54515 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54515, GHSA-5jmj-h7xm-6q6v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59888 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-59888, GHSA-3pjw-73gf-8qr5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59889 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-59889, GHSA-5gvw-p9qm-jgwh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-68494 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-68494, GHSA-r7wm-3cxj-wff9]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startNegativeNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startPositiveNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.async.ByteArrayFeeder] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [com.fasterxml.jackson.core.exc.StreamConstraintsException] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.async.ByteArrayFeeder, com.fasterxml.jackson.core.exc.StreamConstraintsException]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68497 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-68497, GHSA-q4xh-88c3-wmh7]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/ext/CoreXMLDeserializers.java] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers, com.fasterxml.jackson.databind.ext.CoreXMLDeserializers$Std]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers.Std._deserialize] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68498 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-77310 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-77310, GHSA-vvgp-rfg2-7rr6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-83557 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-83557, GHSA-gx83-3vf8-gh7j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator.isUnsafeBaseType] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89407 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [com.fasterxml.jackson.core.io.NumberInput]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.io.NumberInput]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-89425, GHSA-7hhh-6rmp-j9qf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser._reportInvalidToken] RESOLVED; classes: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91776 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-91776, GHSA-wv8q-qhhj-9h54]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase._findDeserializer] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91777 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-91777, GHSA-cxp5-3px4-pw24]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.CollectionDeserializer.CollectionReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.MapDeserializer.MapReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-9828, GHSA-p47f-322f-whfh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - GHSA-mhm7-754m-9p8w com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1534 dependency or exclusion origins.
[INFO]   Maven supplied no source location/identity or the location matched zero or
[INFO]   multiple original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the analyze goal):
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) {nodeId=n3} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) {nodeId=n2} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-text:jar:1.9 (compile) {nodeId=n1} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.codehaus.janino:janino:jar:3.1.12 (compile) {nodeId=n4} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) {nodeId=n6} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) {nodeId=n5} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) -> ch.qos.logback:logback-core:jar:1.5.18 (compile) {nodeId=n9} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) -> org.slf4j:slf4j-api:jar:2.0.17 (compile) {nodeId=n10} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) -> com.fasterxml.jackson.core:jackson-annotations:jar:2.19.0 (compile) {nodeId=n7} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) -> com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) {nodeId=n8} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.codehaus.janino:janino:jar:3.1.12 (compile) -> org.codehaus.janino:commons-compiler:jar:3.1.12 (compile) {nodeId=n11} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) {nodeId=n17} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.12.2 (test) {nodeId=n19} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-params:jar:5.12.2 (test) {nodeId=n18} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> io.micrometer:micrometer-observation:jar:1.15.0 (compile) {nodeId=n16} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-aop:jar:6.2.7 (compile) {nodeId=n12} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-beans:jar:6.2.7 (compile) {nodeId=n13} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-core:jar:6.2.7 (compile) {nodeId=n14} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-expression:jar:6.2.7 (compile) {nodeId=n15} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.apiguardian:apiguardian-api:jar:1.1.2 (test) {nodeId=n24} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.junit.platform:junit-platform-commons:jar:1.12.2 (test) {nodeId=n23} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.opentest4j:opentest4j:jar:1.3.0 (test) {nodeId=n22} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.12.2 (test) -> org.junit.platform:junit-platform-engine:jar:1.12.2 (test) {nodeId=n25} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> io.micrometer:micrometer-observation:jar:1.15.0 (compile) -> io.micrometer:micrometer-commons:jar:1.15.0 (compile) {nodeId=n21} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-core:jar:6.2.7 (compile) -> org.springframework:spring-jcl:jar:6.2.7 (compile) {nodeId=n20} [RETAINED]
[INFO]   JAR trim cache: unavailable (Analyze reports an in-memory prediction only)
[INFO]   Analysis report: <PROJECT_ROOT>/examples/example-cve-unused-app/target/dependency-elider-analysis-report.json
[INFO]   Class usage report: <PROJECT_ROOT>/.scratch/transcript-analysis/analyze-cve-unused-app-class-usage.json
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:analyze-cve-unused-app -->

### Analysis Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `-Delide.traceFiles` | *(none)* | Comma-separated paths to runtime telemetry traces (required). |
| `-Delide.trimJars` | `false` | When `true`, simulates intra-JAR trimming and evaluates CVE absence proofs without modifying files. |
| `-Delide.trimWorkers` | `4` | Maximum worker threads for JAR preparation, closure analysis, and archive sanitization. Actual concurrency is also capped by available processors and pending work; `1` runs sequentially. |
| `-Delide.retainedArtifacts` | *(empty)* | Comma-separated coordinates (`groupId:artifactId[:version[:type[:classifier]]]`) to retain regardless of trace evidence. |
| `-Delide.banishedDependencies` | *(empty)* | Comma-separated exact, trimmed `groupId:artifactId` requests; wildcards and version/type/classifier fields are unsupported. Matched or pre-resolution-excluded requests require `elide.sourceRootsComplete=true` or `elide.productionClassesComplete=true` (mutually exclusive). A matching unsupported Maven scope or artifact type fails closed. Analyze predicts matched, pre-resolution-excluded, or unmatched outcomes and never applies them; Elide applies only a validated plan before publication. |
| `-Delide.productionOutput` | *(empty)* | Path to compiled classes (e.g. `target/classes`) to enable static code reference scanning. |
| `-Delide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader SPI roots; when `false`, prunes unproven SPI roots. |
| `-Delide.reportFile` | `target/dependency-elider-class-usage.json` | Path for the class-usage analysis report. |

Only resolved regular JARs in `compile` and `runtime` scopes are considered for elision. Non-JAR artifacts and other dependency scopes are always retained.

---

## 4. Active Build Elision (`elide`)

The `elide` goal runs in Maven's `INITIALIZE` lifecycle phase, removing unused dependencies and trimming unreferenced classes before compilation and packaging plugins execute.

### Step 1: Enable the Core Extension

To enable whole-artifact dependency removal, declare the core extension in the consumer project's `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>io.github.spockz</groupId>
    <artifactId>dependency-elider-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </extension>
</extensions>
```

> **Important**: Without this extension, ordinary trace-derived whole-artifact drops normally remain retained, though retained-JAR trimming still functions. When an explicit ban is requested, Elide uses isolated current-model Resolver planning and may also evaluate unrelated trace-derived drops; both ban-driven and ordinary drops require graph and retained-content closure before publication.

The persisted Elide summary records applied-ban outcomes in `appliedBans`: matched artifacts are `FORCED_ABSENT_AFTER_RESOLUTION`, declarations removed before resolution are `EXCLUDED_BEFORE_RESOLUTION`, and unmatched requests are `UNMATCHED`. Unmatched requests are not applied and do not prove absence. `rawDroppedCoordinates` excludes policy-forced absences, while total absent-artifact metrics include them.

### Step 2: Run the Elision Build

Invoke `elide` on the command line alongside your build goals:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true
```

Or configure the execution permanently in `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.github.spockz</groupId>
      <artifactId>dependency-elider-maven-plugin</artifactId>
      <version>0.1.0-SNAPSHOT</version>
      <executions>
        <execution>
          <goals>
            <goal>elide</goal>
          </goals>
        </execution>
      </executions>
      <configuration>
        <traceFiles>
          <traceFile>target/classes.log</traceFile>
        </traceFiles>
        <trimJars>true</trimJars>
      </configuration>
    </plugin>
  </plugins>
</build>
```

### Elision Configuration Reference

| Option | Default | Description |
| :--- | :--- | :--- |
| `elide.skip` | `false` | Disables elision and trimming when set to `true`. |
| `elide.leafOnly` | `true` | Restricts dependency elision and intra-JAR trimming to leaf modules in multi-module Maven reactors. Intermediate modules with downstream reactor dependents or `pom` packaging skip elision, allowing internal libraries to build and test against standard dependencies and leaving definitive elision to final application packaging modules. Set to `false` to analyze every module. |
| `elide.traceFiles` | *(none)* | Comma-separated paths to runtime telemetry traces (required). |
| `elide.trimJars` | `false` | Enables ProGuard Core link closure to trim unreferenced classes from retained JARs. |
| `elide.trimWorkers` | `4` | Maximum worker threads for JAR preparation, closure analysis, and archive sanitization. Actual concurrency is also capped by available processors and pending work; `1` runs sequentially. |
| `elide.preconditionClassPathComplete` | `false` | Opts into exact prerequisite-class proof during trim-enabled publication. Set `true` only when all declared Maven class-bearing inputs are present and enumerable before `INITIALIZE`. Proof also requires a known Maven Compiler Plugin version from 3.13 through 3.x, explicit `maven.compiler.proc=none` for both `compile` and `testCompile`, and Java release or source/target levels of at least 11. Detected processor paths/lists/argument channels, compiler arguments other than diagnostic-only `-Xlint:all`, compiler plugin dependencies, custom compiler modes, interface assertions, custom generated-source roots, configured clean/site executions with unmodeled ordering, Enforcer executions at or after inventory capture or with unknown phases, filtered resources, unmodeled pre- or post-`INITIALIZE` plugin executions, custom roots/extensions/packaging, missing, unresolved, and conflicting settings, or direct/multiple Maven goal sequences suppress proof. The default generated production and test source roots under `<build.directory>` are inventoried. |

Packaging is modeled only for maven-shade-plugin 3.6.0 with one `package`/`shade` execution and one built-in manifest transformer whose `mainClass` is resolved. The inherited signature-only resource exclusions in the examples are allowed. Other Shade filters, transformers, inputs, dependencies, source-JAR properties, or custom maven-jar-plugin configuration suppress proof.
If the requested lifecycle reaches `test`, the guard also requires the standard Maven Surefire Plugin 3.5.2 `default-test` execution and explicit `-DskipTests=true`. Test source compilation remains enabled and its classes stay in the inventory; baseline fixture runs do not skip their tests.
| `elide.sourceRootsComplete` | `false` | Set `true` only if all production and generated sources exist before `INITIALIZE` with no downstream generation. When `false`, all compile-classpath JARs and classes are conservatively retained. |
| `elide.assumeConventionalJavaSourceLayout` | `true` | Allows the documented conventional Java source-root translation when exact-path lookup does not locate a structured source claim. Set `false` to require an exact archive path. It never waives complete bytecode attribution or verified artifact identity. The assumption is saved in proof/report provenance; `report` uses the value from the last successful elision snapshot. |
| `elide.productionClassesComplete` | `false` | Asserts that production output contains all compiled production classes. With the Maven extension enabled, this rebinds the default `elide` execution from `initialize` to `process-classes`; the output directory defaults to `${project.build.outputDirectory}` and must contain at least one `.class` file. This assertion is separate from trusted precondition capture: direct CLI goals and missing/other phases keep conservative provider-generation guards. It cannot be combined with `elide.sourceRootsComplete=true`. After compile, bytecode references are unioned with attributed references from compile source roots to retain dependencies used only through inlined constants. |
| `elide.trimRoots` | *(none)* | Comma-separated additional root classes (e.g. `com.example.AppRoot`). |
| `elide.trimSkipArtifacts` | *(none)* | Comma-separated coordinates of retained JARs to keep byte-identical. Their classes serve as roots for sibling closure. |
| `elide.snykEnabled` | `false` | Query Snyk for project package findings during `analyze` and `elide`. Requires an authorized API account, `SNYK_TOKEN`, and an organization ID. |
| `elide.snykOrgId` | `SNYK_ORG_ID` | Snyk organization ID for the optional package-issues API. |
| `elide.snykApiBaseUri` | `https://api.snyk.io` | Snyk regional HTTPS API origin; only supported Snyk API hosts are accepted. |
| `elide.retainDuplicateClassOwners` | *(none)* | Comma-separated class names or globs (`*` within a package, `**` across packages, e.g. `org.example.**`). When a matching class is present in several dependency JARs, every owning JAR is retained whole and byte-identical, including owners that would otherwise be dropped. Unmatched duplicates still fail the build. |
| `elide.trimDuplicateClassOwners` | *(none)* | Comma-separated class names or globs with the same syntax. Every matching duplicate class is kept in every owning JAR, including owners that would otherwise be dropped; with `trimJars=true`, their other unused classes can still be trimmed. If both lists match a class, `retainDuplicateClassOwners` wins; the same pattern in both lists is rejected. |
| `elide.mrjarStrategy` | `vertical-shading` | With `trimJars=true`, `vertical-shading` elevates and trims the configured compiler release view. Higher-tier entries are preserved while their analyzed bodies retain sibling dependencies. Set to `pass-through` to preserve the entire multi-release input JAR byte-identically; when another dependency is trimmed, the unchanged MRJAR still contributes closure through the Maven runtime release. |
| `elide.failOnUnsupportedModuleInfo` | `false` | When `false`, JARs with root `module-info.class` pass through unchanged on the classpath. When `true`, they fail the build. |
| `elide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader dynamic roots declared in `META-INF/services/`. When `false`, unproven SPI roots are pruned. |
| `elide.summaryFile` | `target/dependency-elider-report.json` | Path for the persisted elision snapshot read by `report`. |
| `elide.analysisSummaryFile` | `target/dependency-elider-analysis-report.json` | Path for the analysis summary. To replay it, pass this path as `elide.summaryFile` to `report`. |
| `elide.sbomFile` | `target/dependency-elider-sbom.cdx.json` | Path for the post-elision CycloneDX 1.6 SBOM. |
| `elide.baselineSbomFile` | `target/baseline-sbom.cdx.json` | Path for the pre-elision baseline CycloneDX 1.6 SBOM. |
| `elide.vexFile` | `target/dependency-elider.openvex.json` | Path for the OpenVEX document written during trim-enabled publication when omission or precondition proof succeeds. |

For example, accept duplicated `org.example.Shared` and keep every provider JAR whole with
`'-Delide.retainDuplicateClassOwners=org.example.Shared'`. To preserve duplicates throughout
a package while allowing unused sibling classes to be trimmed, use
`-Delide.trimJars=true '-Delide.trimDuplicateClassOwners=org.example.**'` instead.
Quote glob arguments so the shell passes them unchanged. The equivalent POM list is:

```xml
<configuration>
  <trimJars>true</trimJars>
  <trimDuplicateClassOwners>
    <className>org.example.**</className>
  </trimDuplicateClassOwners>
</configuration>
```

### Preserving Metadata and Special JARs

Set `-Delide.trimWorkers=2` to cap trimming at two workers. This setting limits the plugin's trimming concurrency; it does not reserve CPU cores or limit other Maven work. The JVM option `-XX:ActiveProcessorCount=N` changes the processor count reported to all Maven code, so it is a Maven-wide limit rather than a plugin-only setting.

* **Framework Roots**: Service providers (`META-INF/services`), Spring factories, and GraalVM native-image configs automatically protect declaring and provider JARs from whole-artifact removal.
* **ServiceLoader SPI Dynamic Roots**: Application bytecode is scanned for constant `ServiceLoader.load` invocations to prove SPI usage. When `conservativeServiceLoaderRoots` is `true` (default), unproven SPI providers are retained for runtime safety. Set it to `false` to permit pruning unproven providers when your application does not need them. Retained declared code prevents omission proof under the common finding checks.
* **Intra-JAR Trimming**: Trimmed JARs are written to `target/elided-artifacts/` with original JARs left untouched. Digital signatures are stripped to maintain archive validity, while resources, licenses, and SPI descriptors are preserved.
* **Multi-Release and Module Descriptors**: With JAR trimming enabled, Elider selects the effective compiler release, then target, as its analysis target; if neither is configured, it uses the active runtime feature as an analysis default. The selected target view is elevated and trimmed. All higher-tier entries remain byte-identical except versioned `module-info.class`, which is removed. Bodies at class-tier breakpoints through the Maven runtime release contribute to sibling closure; tiers above that runtime remain outside the verified linkage boundary. The active JDK class table comes from Maven's runtime and does not emulate a historical target API. Set `elide.mrjarStrategy=pass-through` to preserve the whole source archive. Root module descriptors keep the existing classpath pass-through behavior.
* **Exact Pass-Through (`trimSkipArtifacts`)**: Pins specified dependencies byte-identical while allowing their classes to resolve external links into trimmed sibling dependencies. Missing references originating in the unchanged JAR are tolerated; reachable missing references from a sibling being transformed still fail analysis. This also applies to retained `provided` and `system` JARs and to dependencies that graph or bytecode reachability requires Elider to retain unchanged. Their resolved bytecode and dynamic roots contribute to sibling closure, including analyzed multi-release tiers. In an `unresolved references` error, the `analysis candidate` is the archive whose closure is being analyzed, while the class before `->` owns the unresolved reference and may be in a different JAR. Select the exact resolved coordinate of a compile/runtime owner for pass-through if it must remain unchanged. An absent dependency's own classes and outgoing references are outside the analyzed graph.
* **Tolerated duplicate classes**: By default duplicate class ownership fails analysis because class-loading order would be ambiguous. `retainDuplicateClassOwners` and `trimDuplicateClassOwners` let you accept specific duplicates explicitly, preserving all providers and the dependency closure of each implementation. Both policies cover the production analysis classpath, including `provided` and `system` owners, which remain untrimmed. Multi-release duplicates use the effective class views through the greater of the analysis target and Maven runtime release; inactive versioned entries do not create duplicate findings. Tolerated duplicates are listed in the build log and under `toleratedDuplicates` in `dependency-elider-report.json` and the Analyze class-usage report (class name, action `RETAIN_JARS` or `TRIM_OTHER_CLASSES`, and owning coordinates). The saved `report` goal replays these findings.
* **Native-image argument policy**: Class roots, package roots, configuration references, and descriptor fields in the audited GraalVM Native Image 21.0.12+7.1 inventory are modeled. Invalid recognized inputs fail clearly. Other syntactically valid arguments are accepted without inferred roots; unknown future options are outside the completeness guarantee. See [ADR-0009](../../../../docs/adr/0009-permissive-graalvm-native-image-metadata-ingestion.md).

### Using Post-Compile Elision and Inspecting the Dependency Tree

For projects with source generators or annotation processors, enable the extension and set `elide.productionClassesComplete=true`, or bind the `elide` execution explicitly to `process-classes`. The extension can rebind an initialize-bound execution before Maven creates the lifecycle plan. Use the normal lifecycle so generation and compilation run before capture. A direct `mvn dependency-elider:elide` invocation does not establish this capture point. Unknown writers at `process-classes` or later remain unsupported; `skipTests` also leaves `testCompile` enabled, so test-compiler safeguards continue to apply.

In this mode, compile-time source references supplement the production bytecode roots. This keeps dependencies whose primitive or `String` constants were inlined by javac, and the same roots seed JAR trimming. Source attribution includes the completed output directory on its classpath and forces `-proc:none`, so annotation processors are not run again. If source roots are missing or empty, include unsupported languages (`.kt`, `.kts`, `.scala`, `.groovy`), use an unsupported compiler mode, or fail javac attribution, the summary warns and conservatively retains every compile-visible artifact and all of their indexed classes. The class-use report remains bytecode and runtime telemetry evidence; source references do not count as runtime reachability or VEX proof. Source-only references may retain unused compile dependencies, and test-only source references are not covered by this production scan.

With `.mvn/extensions.xml` and an active `initialize` or `process-classes` elider execution, run `dependency:tree` to inspect the post-elision graph directly. A process-classes binding injects that phase before the tree request unless an equal or later lifecycle phase already appears before it:

```sh
mvn dependency:tree
```

---

## 5. Viewing Elision Reports (`report`)

The `report` goal displays the summary and mediated dependency graph from the last successful `elide` run without re-executing dependency analysis:

`exclusionReview` saves repeated exact exclusions observed on frozen pre-injection effective
dependency rows, including separate declaration and exclusion origins. Findings are advisory and
exclude wildcard coordinates; noncontributing management exclusions and incomplete provenance are
reported separately. An unavailable capture is explicit. Maven path exclusions affect collection
and mediation, while a global post-resolution ban affects project output and can remove content
needed by consumers. No POM edits or behavioral equivalence are implied. The Analyze class-usage
report contains the same review, and the `report` goal replays the saved elision review.

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
```

### Report Information

* **Dropped Artifacts**: Total count and original on-disk JAR bytes of elided dependencies.
* **Pruned Classes**: Count and uncompressed `.class` payload bytes removed from dropped JARs and retained JARs (metrics never overlap).
* **Vulnerability Status**: Separates common package/code findings and unresolved review claims from verified classifications. OSV, CVE List and manual inputs retain provenance for reporting and use the same effective-finding assessment. Automatic normalized code sets and affected-version coverage union, preserving version gaps and code applicability; explicit manual fields override within matching scope and omitted fields enrich. Severity is ignored. Manual `LOW`/`MEDIUM` retains review-only intent and cannot be bypassed by automatic enrichment. Verification requires exact version binding, attributable declared code and physical absence, or complete opted-in prerequisite inventory. Unsupported or ambiguous code remains visible rather than producing a proof. Removed, trimmed and unchanged are inventory facts, not mitigation. The saved `report` goal replays findings, attribution and assumptions without reassessment. Publication and stale-file cleanup retain their digest-bound transaction rules. With `elide.trimJars=false`, SBOM/OpenVEX publication and stale OpenVEX cleanup are not run. See [VEX Evidence Boundary](#vex-evidence-boundary).
* **Mediated Graph**: Visualizes shortest dependency paths with node dispositions: `[RETAINED]`, `[CLASS_TRIMMED]`, `[EFFECTIVE_DROP]`, or `[PROTECTED]`.
* **Format Versions**: Internal persisted report and cache formats use independent schema version 1; incompatible payloads fail fast with instructions to rerun `elide`. CycloneDX declares `specVersion` 1.6 and OpenVEX uses its 0.2.0 context URL. The top-level `version` in either generated security document is a document revision counter, not a schema version.

---

## 6. Vulnerability Intelligence & OpenVEX

Maven Dependency Elider syncs vulnerability metadata from the official OSV Maven snapshot (`-Delide.osvSnapshotUri`) and the CVEList v5 repository (`-Delide.cveListGitUri`).

Both inputs can independently produce Maven findings when their identity/version information is supported. Configured `<vulnerabilityMappings>` joins those findings for the current project; manual rows are not written to the shared external index. Automatic path/class/routine details normalize into sets, and affected versions union without filling gaps between disjoint ranges. A declared code path keeps its version scope even when package coverage is wider. Unsupported claims remain explicit and do not manufacture a Maven identity.

Manual supplied fields have higher priority for the same CVE, component and applicable version. An explicit manual code mapping replaces the automatic class/file/routine group; omitted fields are enriched. All effective values then use the same validation and verification. Source names are report attribution rather than proof authority; severity scores do not influence merging. See [ADR-0014](https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/0014-source-independent-vulnerability-findings.md).

### Optional Snyk package findings

To query Snyk during `analyze` or `elide`, configure `SNYK_TOKEN` and `SNYK_ORG_ID` in the environment and set `-Delide.snykEnabled=true`. Alternatively, pass the organization ID with `-Delide.snykOrgId=...`. Use the regional API origin for the organization if it is not hosted at the default endpoint. Enabling this option sends the project's queried Maven package coordinates to Snyk and requires an account entitled to use its package-issues API.

The API is queried for each supported concrete project artifact, including transitive dependencies present in the input inventory. Its findings apply only to the exact queried version, retain Snyk and CVE identifiers, and merge with other findings. This is a project-scoped lookup, not a download or local copy of Snyk's full database; the separately licensed Application Feed is not consumed by this option. Snyk observations are reported independently, including incomplete and failed queries. Their revision is a local fingerprint of the query results, not a Snyk database revision. Rate-limited or unauthorized requests leave the observation incomplete. Offline execution sends no requests and reports the enabled source as unavailable.

### Refreshing the Vulnerability Cache

Update the local vulnerability database on demand:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:update-cve-index
```

* **Cache location**: Stored in the OS user cache directory (outside `~/.m2`); override via `-Delide.cveCacheDirectory=/path/to/cache`.
* **Freshness TTL**: Defaults to 24 hours (`-Delide.cveCacheTtlHours=24`). Use `-Delide.cveForceSync=true` to force synchronization.
* **Offline resilience**: Offline builds read a validated, producer-compatible generic cache without network access or CVE checkout scanning. Missing or invalid cache state is reported as unavailable, rather than successful empty coverage. Project-local manual mappings can still be assessed.

OSV and CVE List keep independent last-good observations. A failed refresh retains that source's last-good claims with a stale/error diagnostic while another source can advance. A successful empty source snapshot is distinct from a failure. A failed cache publication preserves the previous published generic snapshot. No project's manual mappings are written to this shared cache.

CVE List and OSV indexing skip malformed affected entries or records while keeping valid siblings from the same refresh. A source with skipped data is marked `PARTIAL`, with a skipped-row count and bounded diagnostic details, so its findings do not imply complete source coverage. An affected entry with an invalid version claim is skipped in full to avoid interpreting the remaining versions as a broader range. A later refresh can repair skipped data; OSV retries a full snapshot after a partial refresh. Unreadable files, damaged archives, an invalid OSV change index, and network or Git failures remain source refresh failures.

The following ZIP and CSV refresh rules describe OSV synchronization. CVE List separately reuses a current partition within its TTL, checks the Git revision when due, and reuses indexed contributions when that revision is unchanged. Offline assessment does not scan the checkout.

The 24-hour TTL measures time since the last successful local synchronization. On a due online refresh with a reusable cached snapshot, the plugin checks the OSV ZIP object's `Last-Modified` metadata with a HEAD request. It downloads the ZIP when source metadata is absent or incompatible, the source timestamp differs, the advertised ZIP timestamp is at least 24 hours old, or `-Delide.cveForceSync=true`; otherwise it reuses the cached snapshot. Any full download uses `Last-Modified` from its successful ZIP GET response as that snapshot's source timestamp, including cold and forced downloads. Each due refresh downloads the complete `Maven/modified_id.csv` and fetches records whose source `modified` value is newer than the staged owner record. Successful responses replace that OSV record's associations; explicit withdrawals remove that owner.

The ZIP timestamp, each OSV record's `modified` value, and local `lastSyncTimestamp` describe different clocks. OSV does not document a shared watermark or CSV deletion events, so synchronization is eventually consistent: upstream publication delay, races, offline builds, failed requests, and removals awaiting a later full ZIP can extend how long local data differs from the source. A successful local sync is not a zero-lag or completeness guarantee.

### Declaring Project Vulnerability Mappings

Map specific vulnerabilities to code symbols in `pom.xml`:

```xml
<configuration>
  <trimJars>true</trimJars>
  <vulnerabilityMappings>
    <vulnerabilityMapping>
      <cveId>CVE-2026-10001</cveId>
      <groupId>org.example</groupId>
      <artifactId>affected-library</artifactId>
      <version>1.2.3</version>
      <versionRangeSpec>[1.2.0,1.3.0)</versionRangeSpec>
      <vulnerableClasses>
        <vulnerableClass>org.example.affected.VulnerableHandler</vulnerableClass>
      </vulnerableClasses>
      <sourceAdvisoryUrl>https://example.invalid/advisory</sourceAdvisoryUrl>
      <confidenceLevel>HIGH</confidenceLevel>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

### Overriding Conservative Multi-Symbol Mappings

When an upstream vulnerability advisory covers a wide version range and maps multiple classes across versions (for example, Jackson Core `CVE-2026-68494` mapping both `ByteArrayFeeder` and `StreamConstraintsException`), the elider's default proof engine conservatively fails closed if any mapped class does not exist in the original dependency JAR (such as versions prior to Jackson 2.15 where `StreamConstraintsException` had not yet been created).

If you inspect the upstream fix commit and determine that only a subset of the mapped classes applies to your specific version, you can declare an explicit POM override targeting your library version. POM overrides take precedence over the indexed mapping:

```xml
<configuration>
  <trimJars>true</trimJars>
  <vulnerabilityMappings>
    <!-- Jackson Core: override index mapping to only require ByteArrayFeeder for pre-2.15 versions -->
    <vulnerabilityMapping>
      <cveId>CVE-2026-68494</cveId>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <versionRangeSpec>[2.14.0,2.15.0)</versionRangeSpec>
      <vulnerableClasses>
        <vulnerableClass>com.fasterxml.jackson.core.async.ByteArrayFeeder</vulnerableClass>
      </vulnerableClasses>
      <!-- Point directly to the upstream fix commit showing the modified file diffs -->
      <sourceAdvisoryUrl>https://github.com/FasterXML/jackson-core/pull/1611</sourceAdvisoryUrl>
      <confidenceLevel>HIGH</confidenceLevel>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

### VEX Evidence Boundary

Every source supplies common effective declarations to the same proof checks. Manual priority affects merging, not proof authority. Omitted-code proof requires exact candidate identity and version, attributable declared classes in the original artifact, and their physical absence from the resulting artifact. Configured manual `LOW`/`MEDIUM` is review-only even if automatic data fills missing fields. `HIGH` alone, a package-only match or a heuristic code name cannot establish proof.

Declared source paths and routines are attributed against the exact original JAR through the shared bytecode-based resolver. Path normalization preserves Java case and package identity; a basename alone is insufficient. Qualified routines retain their declaring owner and any supplied signature, and ambiguous ownership or unsupported attribution suppresses the corresponding proof. `elide.assumeConventionalJavaSourceLayout` controls the documented source-root translation, not evidence completeness. No particular JDK vendor/build or in-process recompilation of third-party source is required. The result is bounded to the verified declared code; it does not establish the vulnerability's independent truth or that every affected code path was declared. Unresolved claims remain visible for review.

The omitted-code proof also requires archive inspection to prove every affected class family absent from the retained candidate's trimmed JAR. A dependency removed entirely is reported as dropped from inventory, not as code-absence VEX.

Core mappings, complete-inventory proof, CycloneDX/OpenVEX serialization, and snapshot-aware assessment support precondition evidence. A mapping must name both the prerequisite Maven coordinate and exact prerequisite class; coordinate-only mappings cannot prove absence. The Maven goal requires the explicit `elide.preconditionClassPathComplete=true` assertion that the declared build inventory is complete, and only uses it when `elide.trimJars=true`. The guard requires a known Maven Compiler Plugin version from 3.13 through 3.x, `maven.compiler.proc=none` for both `compile` and `testCompile`, and Java release or source/target levels of at least 11. It checks active and managed compiler plugin configuration plus project and Maven session properties, and rejects detected processor paths, processor lists, compiler arguments other than diagnostic-only `-Xlint:all`, compiler plugin dependencies, custom compiler modes, interface assertions, custom generated-source roots, configured clean/site executions with unmodeled ordering, filtered resources, and unresolved or conflicting settings. It inventories `<build.directory>/generated-sources/annotations` and `<build.directory>/generated-test-sources/test-annotations` even before Maven adds those roots. Pre-capture Enforcer rules are limited to `requireJavaVersion`, `requireMavenVersion`, `requirePluginVersions`, `banDuplicatePomDependencyVersions`, `dependencyConvergence`, and `requireUpperBoundDeps`; custom rule implementations and Enforcer plugin dependencies suppress proof. It also rejects unmodeled plugin executions before and after `INITIALIZE`, custom packaging/extensions, unmodeled compiler or resource roots, and Maven request sequences other than one default-lifecycle goal optionally preceded by one `clean` goal. This opt-in cannot override detected downstream generators. It checks application classes/resources and all effective post-elision dependency archives, binds the result to an inventory fingerprint and per-file digests, and suppresses evidence if any inventory input or provider is unknown. The Maven publisher shares that captured inventory with assessment and both output formats, revalidates provider membership and content before commit, and publishes all files through one rollback transaction. The claim covers only that declared Maven inventory; it cannot prove absence of classes introduced by later packaging or external runtime mechanisms. OpenVEX uses a free-form impact statement without a justification because no OpenVEX justification enum accurately describes the missing prerequisite. When no qualifying VEX remains, a prior file is removed only if its exact path and digest match the generated-output manifest; otherwise it is preserved. With `elide.trimJars=false`, VEX output and stale-file cleanup do not run. See [ADR-0008](https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/0008-precondition-gated-vex-attestations.md) and [RQ-0013](https://github.com/spockz/maven-dependency-elider/blob/main/docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
The package guard supports `jar` and `pom` projects and accepts only maven-shade-plugin 3.6.0 with one `package`/`shade` execution and a built-in manifest transformer with a resolved `mainClass`. Any request that reaches a modeled JAR package execution must include `clean` first so the standard JAR plugin cannot reuse an older archive; Shade packaging is covered as an additional package path. Clean skip/exclusion/failure overrides and deferred clean modes suppress proof. It allows only the inherited signature-resource exclusions shown in the examples. `war` and `maven-plugin` packaging, other Shade filters, transformers, inputs, dependencies, source-JAR properties, custom maven-jar-plugin configuration, and resource-plugin dependencies suppress proof.

---

## 7. Comparing SBOMs with OSV-Scanner

To verify vulnerability reduction across baseline and post-elision inventories, run the automated comparison:

```sh
make scan-sbom
```

This runs OSV-Scanner offline against both `target/baseline-sbom.cdx.json` and `target/dependency-elider-sbom.cdx.json`, generating reports in `target/sbom-comparison/`:

* `baseline-scan.json`: Raw scanner findings on the untrimmed baseline inventory.
* `post-elision-scan.json`: Raw scanner findings on the post-elision inventory.
* `comparison-report.json`: Hash-verified summary of eliminated versus remaining package-level findings.
