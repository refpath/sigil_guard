# Library maintenance

The Hex package contains runtime modules, integration guides and notebooks.
Development instructions live in the source repository, in
[AGENTS.md](https://github.com/refpath/sigil_guard/blob/main/AGENTS.md) and the
[repository
workflows](https://github.com/refpath/sigil_guard/tree/main/.agents). Clone the
repository to run its tests or development scripts; the Hex package does not
include them.

The core runtime dependencies are Jason, NimbleOptions and Telemetry. HTTP
transports, authentication and durable cross-boot trust state belong to the host.
