<!-- WHY: Introduces the project, its current scope, and the supported contributor workflow at the repository entry point. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Maven Dependency Elider is an early-stage Java project exploring runtime-informed dependency analysis for Maven applications. The goal is to use observed class-loading data to identify dependencies that an application does not use, then make those findings available to Maven builds and downstream packaging tools.

The project is under active development. The core currently includes runtime trace readers, a JAR central-directory class index, and an initial conservative dependency-pruning engine. The Maven `elide` goal, cache, provenance outputs, bytecode slicing, and end-to-end elision workflow are still being implemented. Do not use this project to remove dependencies from production builds.

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
