<!-- WHY: Introduces the project, its current scope, and the supported contributor workflow at the repository entry point. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Maven Dependency Elider is an early-stage Java project exploring runtime-informed dependency analysis for Maven applications. The goal is to use observed class-loading data to identify dependencies that an application does not use, then make those findings available to Maven builds and downstream packaging tools.

The project is under active development. The core currently includes runtime trace readers, a JAR central-directory class index, an initial conservative dependency-pruning engine, and a cache API. The cache is not integrated into the Maven plugin, and the `elide` goal, provenance outputs, bytecode slicing, and end-to-end elision workflow are still being implemented. Do not use this project to remove dependencies from production builds.

## Project goals

- Use runtime observations such as class-loading logs and JVM class lists to inform dependency usage analysis.
- Integrate analysis with Maven and surface results early in the build lifecycle.
- Preserve accurate dependency and provenance information for downstream packaging and security tools.
- Keep the build and analysis fast enough for routine developer workflows.

These are development goals; the current core components are not yet exposed as a production-ready Maven workflow.

## Repository layout

| Path | Purpose |
| --- | --- |
| `elider-core/` | Core model and, as development progresses, dependency analysis components. |
| `dependency-elider-maven-plugin/` | Maven plugin module. |
| `elider-benchmarks/` | Performance benchmark module. |
| `examples/` | Example Maven applications for integration work. |
| `docs/adr/` | Accepted architecture decision records. |
| `docs/research/` | Research notes and implementation handovers. |

## Requirements

- JDK 21 or newer. The project compiles with Java 21 language and API compatibility.
- A POSIX shell and `make` for the documented developer commands.
- Node.js and `npm` to install the Markdown linter used by `make check`.

The Maven Wrapper is included, so a separate Maven installation is not required.

## Build and checks

Install the documentation linter once, then run the repository check:

```sh
make tools
make check
```

`make check` formats Java sources, runs Checkstyle, PMD, SpotBugs, lints Markdown, and runs the core and Maven plugin tests. Run individual checks with `make lint-java`, `make lint-markdown`, `make test-core`, or `make test-plugin`.

## Cache benchmarks

The JMH cache benchmarks measure fresh metadata fingerprinting, complete decision cache loading, and the combined fingerprint plus lookup over 100 local artifact fixtures. They exercise the core cache API only; they do not measure a Maven plugin fast path or establish the whole-build sub-10ms target. Build the standalone JMH runner and run these methods from the repository root with:

```sh
./mvnw -pl elider-benchmarks -am package
java -jar elider-benchmarks/target/benchmarks.jar '.*ElisionCacheBenchmark.*' \
  -f 2 -wi 3 -i 5 -w 1s -r 1s
```

JMH reports the fork, warmup, measurement, and JVM metadata. Record hardware, operating system, and filesystem separately when comparing runs.

### Recorded run

With JMH 1.37 on GraalVM JDK 25.0.5, the command above measured:

| Benchmark | Average time | 99.9% confidence interval |
| --- | ---: | ---: |
| Fresh metadata fingerprinting | 0.221 ms/op | ±0.043 ms/op |
| Complete decision cache load | 0.722 ms/op | ±0.011 ms/op |
| Fingerprinting plus cache lookup | 1.078 ms/op | ±0.302 ms/op |

The cache load result exceeds the research note's 0.5 ms component budget. The combined result measures the core cache API only; the cache is not integrated into the Maven plugin, so it does not prove lifecycle or whole-build overhead. The recorded environment was an AMD Ryzen 9 5900X 12-core processor (12 cores, 24 threads) and Linux 7.2.9-1-cachyos-bore-lto x86_64. Benchmark fixtures were created under `/tmp` on overlay storage; the workspace mount is Btrfs. The benchmark run used 2 forks, 3 warmup iterations, and 5 measurement iterations of 1 second each. The results are specific to this run and environment.

## Example applications

The `examples/` reactor contains two consumer applications used to exercise the eventual record, elide, package, and runtime-verification workflow:

- **`example-basic-app`** is a plain Java application that uses Jackson to print `{"message":"hello"}`. Its shaded executable JAR is the packaging fixture; `commons-codec` is included as an unused dependency candidate.
- **`example-spring-boot-app`** is a Spring Boot web application with a `GET /api/hello` endpoint. Its `HelloControllerTest` exercises the endpoint, and `spring-boot-starter-mail` is included as an unused starter candidate.

The fixtures currently demonstrate application behavior, tests, and downstream packaging configuration. The automated dependency recording and elision cycle is not yet available. Build the examples with:

```sh
./mvnw -f examples/pom.xml verify
```

## Usage

The Maven plugin provides a nonmutating, trace-based `analyze` goal. Install the plugin and its core dependency to the local repository, then run it in the consumer project with an explicit trace:

```sh
# From this repository root:
./mvnw -pl dependency-elider-maven-plugin -am install

# From the consumer project, use its Maven binary or wrapper:
./mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

See [Maven plugin usage](docs/plugin-usage.md) for supported trace formats, summary fields, and global exclusions. The `elide` goal remains disabled before any Maven project state is accessed until a forked Maven 3.9 build proves that INITIALIZE mutation survives later resolution, compile/test classpath construction, and packaging. Maven 4 compatibility remains unverified.

## Contributing

Contributions are welcome. Before opening a pull request, run `make check` and include tests for behavior changes. For larger design changes, consult the relevant [architecture decisions](docs/adr/) and [research documents](docs/research/) first.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the complete text.

This project is co-created with Codex and Gemini.
