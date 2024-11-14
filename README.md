# parascope

Weggli ruleset scanner for binaries and source code. Organise your weggli
rules and scan source code and binaries in parallel!

## Build/installation

To build and install parascope requires IDA Pro v9.0 and access to the
latest SDK.

Install via crates.io:

```sh
export IDASDKDIR=/path/to/sdk
cargo install parascope
```

Build/install from source:

```sh
export IDASDKDIR=/path/to/sdk
cargo install --path .
```

## Examples and usage

Scan a single binary and output the rule matches to stdout:
```
parascope --display -r rules /path/of/binary
```

Scan all binaries in the given directory and stream rule matches to results.jsonl:
```
parascope -o results.jsonl -r rules /directory/of/binaries
```

Scan the C source code in the given directory and stream rule matches to results.jsonl:
```
parascope -m c -o results.jsonl -r rules /directory/of/source-code
```

Complete set of capabilities:

```sh
Weggli ruleset scanner for source code and binaries

Usage: parascope [OPTIONS] --rules <rules> <INPUT>

Arguments:
  <INPUT>
          File or directory to scan

Options:
  -m, --mode <mode>
          Analysis mode

          [default: binary]

          Possible values:
          - binary: Binary analysis mode (using IDA)
          - c:      Source code analysis mode (C)
          - cxx:    Source code analysis mode (C++)

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

  -o, --output <OUTPUT>
          File to write output results (JSONL)

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Rules

We use [weggli-ruleset](https://github.com/xorpse/weggli-ruleset.git) to help
manage weggli patterns. It provides a yaml-based rule format that allows
different (related) patterns to be grouped along with metadata useful for
categorising and triaging matches. For example, we can encode the patterns from
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

### Rulesets & Resources

Below is a list of resources containing weggli patterns/rules that can easily
be ported to parascope rules:

- [weggli-patterns](https://github.com/0xdea/weggli-patterns) and [A collection of weggli patterns for C/C++ vulnerability research](https://security.humanativaspa.it/a-collection-of-weggli-patterns-for-c-cpp-vulnerability-research/) by [raptor/@0xdea](https://github.com/0xdea)
- [weggli-patterns](https://github.com/plowsec/weggli-patterns) by [volodya/@plowsec](https://github.com/plowsec)
- [Playing with Weggli](https://dustri.org/b/playing-with-weggli.html) by [Julien Voisin](https://dustri.org/)
- [Weggli rules (SSTIC 2013)](https://github.com/synacktiv/Weggli_rules_SSTIC2023) by [Synacktiv](https://github.com/synacktiv)
