<!-- WHY: Guides contributors on development environment requirements, repository layout, build and test commands, and benchmarking procedures. -->
# Contributing to Maven Dependency Elider

Contributions are welcome. Before opening a pull request, run `make check` and include tests for behavior changes. For larger design changes, consult the relevant [architecture decisions](docs/adr/) and [research documents](docs/research/) first.

## Contributor requirements

To build the project locally, run linters, and execute the full test verification suite, you need:

- **JDK 21 or newer**. The project compiles with Java 21 language and API compatibility.
- **A POSIX shell and `make`** for the documented developer commands.
- **Node.js and `npm`** to install the Markdown linter (`markdownlint-cli2`) used by `make check`.
- **Bash and the `timeout` utility** for `make test-examples`. Node.js is already required for Markdown linting; the example helpers use only its built-in modules and the JDK `jar` command.
- *(Optional)* **Caddy** (`https://caddyserver.com`) to preview the documentation site locally with `make serve`.

The Maven Wrapper (`mvnw`) is included in the repository, so a separate Maven installation is not required.

## Repository layout

| Path | Purpose |
| --- | --- |
| `elider-core/` | Core analysis, graph pruning, ProGuard-based bytecode slicing, and CycloneDX SBOM/VEX generation components. |
| `dependency-elider-maven-plugin/` | Maven plugin module providing the `analyze` and `elide` Mojos and plugin documentation site. |
| `elider-benchmarks/` | Performance benchmark module containing JMH microbenchmarks. |
| `examples/` | Example consumer applications (Basic App, Spring Boot App, CVE fixtures) for integration tests. |
| `docs/adr/` | Accepted Architecture Decision Records (ADRs). |
| `docs/research/` | Research questions (RQs), empirical benchmarks, and technical investigations. |
| `docs/handovers/` | Session handovers and continuity notes. |
| `scripts/` | Deterministic build and documentation helper scripts. |

## Build and checks

Install the documentation linter once, then run the repository check:

```sh
make tools
make check
```

`make check` formats Java sources, runs Checkstyle, PMD, SpotBugs, lints Markdown, and runs the core and Maven plugin tests. Run individual checks with:

- `make lint-java` — Run Checkstyle, PMD, and SpotBugs.
- `make lint-markdown` — Run `markdownlint-cli2` across all documentation.
- `make test-core` — Run `elider-core` unit tests.
- `make test-plugin` — Run Maven plugin tests with reactor dependencies.
- `make test-examples` — Run end-to-end integration cycles across example applications.
- `make site` — Build the plugin documentation site locally.
- `make serve` — Build and serve the documentation site locally with Caddy (default: `http://localhost:8080`, configurable with `SERVE_PORT=<port>`).

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
| :--- | ---: | ---: |
| Fresh metadata fingerprinting | 0.221 ms/op | ±0.043 ms/op |
| Complete decision cache load | 0.722 ms/op | ±0.011 ms/op |
| Fingerprinting plus cache lookup | 1.078 ms/op | ±0.302 ms/op |

The cache load result exceeds the research note's 0.5 ms component budget. The combined result measures the core cache API only; the cache is not integrated into the Maven plugin, so it does not prove lifecycle or whole-build overhead. The recorded environment was an AMD Ryzen 9 5900X 12-core processor (12 cores, 24 threads) and Linux 7.2.9-1-cachyos-bore-lto x86_64. Benchmark fixtures were created under `/tmp` on overlay storage; the workspace mount is Btrfs. The benchmark run used 2 forks, 3 warmup iterations, and 5 measurement iterations of 1 second each. The results are specific to this run and environment.
