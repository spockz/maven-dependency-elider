<!-- WHY: Introduces the project, its current scope, and the supported contributor workflow at the repository entry point. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Maven Dependency Elider is an early-stage Java project exploring runtime-informed dependency analysis for Maven applications. The goal is to use observed class-loading data to identify dependencies that an application does not use, then make those findings available to Maven builds and downstream packaging tools.

The project is under active development. The current repository contains the Maven multi-module skeleton, initial core model types, and build checks. Runtime trace readers, dependency analysis, artifact removal, and the Maven `elide` goal are not implemented yet. Do not use this project to remove dependencies from production builds.

## Project goals

- Use runtime observations such as class-loading logs and JVM class lists to inform dependency usage analysis.
- Integrate analysis with Maven and surface results early in the build lifecycle.
- Preserve accurate dependency and provenance information for downstream packaging and security tools.
- Keep the build and analysis fast enough for routine developer workflows.

These are development goals, not features available in the current release.

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

`make check` formats Java sources, runs Checkstyle, PMD, SpotBugs, lints Markdown, and runs the core module tests. Run individual checks with `make lint-java`, `make lint-markdown`, or `make test-core`.

## Usage

The Maven plugin goal and runtime analysis pipeline are not available yet. Follow the project status and implementation notes in [`docs/research/`](docs/research/) for current work.

## Contributing

Contributions are welcome. Before opening a pull request, run `make check` and include tests for behavior changes. For larger design changes, consult the relevant [architecture decisions](docs/adr/) and [research documents](docs/research/) first.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the complete text.
