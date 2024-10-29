# wegglir

Weggli(r) ruleset scanner for binaries and source code. Organise your weggli
rules and scan source code and binaries in parallel!

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
