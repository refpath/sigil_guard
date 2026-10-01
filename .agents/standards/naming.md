# Naming

Use these terms when editing public documentation or API explanations.

| Term | Meaning |
|------|---------|
| SigilGuard | Project and Hex package name. |
| sigil | Project idiom and compatibility heritage. |
| Agent Trust Profile | SigilGuard-owned profile for embedded runtime decisions. |
| Trust Bundle | Signed local keys, tools, policies, patterns, and revocations. |
| Attestation | Signed typed statement about request, result, or decision evidence. |
| Capability Manifest | MCP tool definition and security properties pinned to a digest. |
| Compatibility Contract | Public API or wire shape current consumers rely on. |
| The reference consumer | Generic name for the private production consumer. |

Keep identifiers, wire fields, commands, error tuples, and measured values exact.
Use legacy terminology only where explaining historical fixtures or deleted API
mappings. Describe the library's implemented mechanism and host responsibility
instead of implying hosted registry discovery or an HTTP transport in the core.
