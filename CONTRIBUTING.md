# Contributing to MMT-Probe

Thank you for your interest in contributing to MMT-Probe! This guide will help you get started.

## How to Contribute

1. **Fork** the repository
2. **Create** a feature branch from `main`
3. **Make** your changes
4. **Test** your changes
5. **Submit** a pull request

## Development Setup

### Prerequisites

- Linux (Ubuntu 20.04+ recommended) or macOS
- GCC 4.9 or later
- GNU Make
- [MMT-DPI](https://github.com/montimage/mmt-dpi) installed at `/opt/mmt/dpi` (or custom path via `MMT_BASE`)
- libconfuse (`sudo apt-get install libconfuse-dev`)

### Building from Source

```bash
git clone https://github.com/montimage/mmt-probe.git
cd mmt-probe
make
```

For a debug build with gdb support:

```bash
make DEBUG compile
```

For verbose compilation output:

```bash
make VERBOSE compile
```

See [docs/installation.md](docs/installation.md) for optional module compilation (DPDK, Kafka, MQTT, Security, etc.).

### Running Tests

```bash
# Offline analysis with a sample PCAP file
sudo ./probe -t test/UA-Exp01.pcap -c mmt-probe.conf
```

## Branching Strategy

- `main` -- Main development branch
- `master` -- Stable release branch
- `feat/<name>` -- Feature branches
- `fix/<name>` -- Bug fix branches
- `docs/<name>` -- Documentation updates

Create your branch from `main`:

```bash
git checkout main
git pull origin main
git checkout -b feat/my-feature
```

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
```

**Types:**
- `feat` -- New feature
- `fix` -- Bug fix
- `docs` -- Documentation changes
- `refactor` -- Code refactoring (no functional change)
- `test` -- Adding or updating tests
- `build` -- Build system or dependency changes
- `perf` -- Performance improvements

**Examples:**
```
feat: add BPF filter support for packet capture
fix: prevent crash when stack-type is not Ethernet
docs: update DPDK configuration guide
```

## Pull Request Process

1. Ensure your code compiles without warnings (`-Wall`)
2. Test with at least one PCAP file to verify no regressions
3. Update documentation if your changes affect configuration or behavior
4. Fill out the PR template completely
5. Link related issues using `Fixes #<issue>`

### PR Review Expectations

- PRs are typically reviewed within a few days
- Maintainers may request changes or ask questions
- Once approved, a maintainer will merge your PR

## Coding Standards

### C Code Style

- **Indentation**: Tabs for indentation
- **Braces**: Opening brace on the same line
- **Naming**: `snake_case` for functions and variables
- **Constants**: `UPPER_SNAKE_CASE` for macros and constants
- **Headers**: Include guards using `#ifndef` / `#define` / `#endif`
- **Memory**: Always check return values of `malloc`/`calloc`; free resources on exit paths

### General Guidelines

- Keep functions focused and reasonably sized
- Add comments for non-obvious logic
- Avoid introducing new compiler warnings
- Use the existing utility functions in `src/lib/` where applicable
- Ensure thread safety when modifying shared data structures

## Reporting Bugs

Use the [Bug Report](https://github.com/montimage/mmt-probe/issues/new?template=bug_report.md) issue template. Include:

- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, compiler version, MMT-DPI version)
- Relevant configuration and log output

## Suggesting Features

Use the [Feature Request](https://github.com/montimage/mmt-probe/issues/new?template=feature_request.md) issue template. Describe:

- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

## Questions?

Open a [Discussion](https://github.com/montimage/mmt-probe/discussions) or reach out to [Montimage](https://montimage.com).
