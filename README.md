# wegglir

Weggli(r) ruleset scanner for binaries and source code. Organise your weggli
rules and scan source code and binaries in parallel!

## Usage

```sh
Weggli(r) ruleset scanner for binaries and source code

Usage: wegglir [OPTIONS] --rules <rules> <mode> <INPUT> [OUTPUT]

Arguments:
  <mode>
          Analysis mode

          [default: binary]

          Possible values:
          - binary: Binary analysis mode (using IDA)
          - c:      Source code analysis mode (C)
          - cxx:    Source code analysis mode (C++)

  <INPUT>
          File or directory to scan

  [OUTPUT]
          File to write output results (JSONL)

Options:
      --path-filter [<path-filter>...]
          Restrict analysis to files matching the given regular expression.
          For C/C++ analysis if no path filters are given analysis is restricted
          to a set of default file extensions:

          C: c, h
          C++: C, cc, cxx, cpp, H, hh, hxx, hpp, h

          For binary analysis, all files will be analysed. If an existing IDB is
          available, e.g., we have both file and file.i64, only the IDB will be
          used for analysis irrespective of the path filter.

      --display
          Render matches to stdout

      --display-context <display-context>
          Number of lines before/after match to render

          [default: 5]

      --summary
          Render tabular summary to stdout

  -r, --rules <rules>
          File or directory containing wegglir rules

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Rules

We use [weggli-ruleset] to help manage weggli patterns. It provides a
yaml-based rule format that allows different (related) patterns to be grouped
along with metadata useful for categorising and triaging matches. For example,
we can encode the patterns from
[here](https://github.com/0xdea/weggli-patterns?tab=readme-ov-file#call-to-unbounded-copy-functions-cwe-120-cwe-242-cwe-676),
as follows:

```yaml
id: call-to-unbounded-copy-functions
description: call to unbounded copy functions
severity: medium
tags:
- CWE-120
- CWE-242
- CWE-676
check-patterns:
- name: gets
  regex: func=^gets$
  pattern: |
    { $func(); }
- name: st(r|p)(cpy|cat)
  regex: func=st(r|p)(cpy|cat)$
  pattern: |
    { $func(); }
- name: wc(r|p)(cpy|cat)
  regex: func=wc(r|p)(cpy|cat)$
  pattern: |
    { $func(); }
- name: sprintf
  regex: func=sprintf$
  pattern: |
    { $func(); }
- name: scanf
  regex: func=scanf$
  pattern: |
    { $func(); }
```
