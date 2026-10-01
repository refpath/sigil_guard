# Quality Gates

Choose checks by the affected surface before committing or handing off. Run
`git diff --check` for every change. Use existing tools; if a prerequisite is
unavailable or installation is outside the task, report the blocked check and
continue independent validation.

| Affected surface | Validation |
|------------------|------------|
| Agent contract, standards, skills, discovery links | Parse frontmatter; check name/directory agreement, distinct triggers, relative references, implicit invocation, tracked/ignored boundaries, and symlink targets. Read the final instructions against realistic tasks; metadata checks alone do not prove selection behavior. |
| Project Markdown, terminology, spec/task references | `mix sigil.docs_lint`; inspect changed links and claims. This is a static documentation check, not proof of runtime semantics. |
| Elixir docs or public guides/notebooks | Formatting and compilation, relevant doctests/consumer assertions, `mix doctor`, and `mix docs --warnings-as-errors`; `mix sigil.livebook_check` when notebook execution or tutorial dependencies change. |
| Runtime behavior or application configuration | Focused regression tests first, then the complete application gate. Include security cases for the changed mechanism. |
| Public contracts or package/release preparation | Complete application gate, `mix sigil.migration_gate`, package contents and generic consumer checks. Release-specific provenance requirements live in `guides/release-and-anchoring.md`. |

`./bin/check` is the complete application gate and clean-clone entry point used
by CI. It fetches locked dependencies and runs ExCheck without retries. The exact
commands and tool configuration live in `.check.exs`; do not duplicate that list
in skills or templates. Use its individual commands to diagnose failures. Do not
run dependency bootstrap or unrelated application suites for guidance-only edits.

Fix failures at their owner, rerun affected checks, and report failures outside
the task. Do not describe a partial run as a complete gate pass. Report command,
exit/result, and material limitations; distinguish skipped, blocked, failed, and
successful checks. Coverage and mutation claims require actual measured output;
hosted CI and live consumer verification require evidence from those environments.
