# MVP Gap Analysis

## What already exists

Prototype-0 already includes the core building blocks of the thesis prototype:

- a CLI entry point in `src/cli.ts`
- static analysis over local source files
- dynamic analysis with Playwright-based browser execution
- a correlation stage that combines static and dynamic findings
- JSON report generation for each stage
- local sample applications under `test-apps/`

In other words, the MVP effort starts from an existing working prototype rather than from a blank project.

## What must be preserved

The next phase should preserve the current repository shape and the working core:

- existing source layout under `src/static`, `src/dynamic`, and `src/correlation`
- existing CLI entry and command families
- existing finding families around DOM, storage, and script-related issues
- existing JSON-reporting approach as the baseline for stabilization
- existing test fixtures and report examples as migration references

The goal is incremental hardening, not architectural replacement.

## Current gaps

The main gaps between the current prototype and a framework-level MVP are:

- configuration and report normalization are implemented, but not all config fields are wired into every stage yet
- static coverage still focuses on a limited rule set, even though HTML inline-script analysis and a few transformed-source DOM-XSS patterns are now included
- correlation quality still depends on heuristic normalization and path matching
- CLI validation and user-facing error handling are still basic
- dynamic execution is limited to a single target URL with a simple wait-based flow
- documentation exists only partially in the repository and is not yet a complete user-facing support layer

## Immediate next improvements

The most useful short-term improvements are:

- strengthen static rule coverage beyond the current DOM, storage, and script patterns
- add lightweight regression fixtures or tests for normalized reports and HTML inline-script findings
- tighten normalized location, sink, storage, and resource matching inputs
- improve command usage messages and failure handling
- make report structures easier to consume consistently in later thesis evaluation steps

These improvements extend the current codebase directly and do not require replacing its modules.

## Planned implementation order

1. Add regression coverage for static, dynamic, and correlation report outputs.
2. Improve static detection quality incrementally, starting from broader source-to-sink and storage pattern handling.
3. Improve correlation matching quality using the more consistent report inputs.
4. Strengthen error handling and CLI flow around missing paths, invalid JSON, and unreachable targets.
5. Expand sample fixtures, reports, and documentation to support repeatable MVP demonstrations.
