# Library Maintenance

The Hex package contains runtime modules, integration guides and notebooks.
Development instructions live in the source repository, in
[AGENTS.md](https://github.com/refpath/sigil_guard/blob/main/AGENTS.md) and the
[repository
workflows](https://github.com/refpath/sigil_guard/tree/main/.agents). Clone the
repository to run its tests or development scripts; the Hex package does not
include them.

The core runtime dependencies are Jason, NimbleOptions and Telemetry. HTTP
transports, authentication and durable cross-boot trust state belong to the host.

## Revalidating Integration Guides

Each integration guide ends with a Compatibility section that records the
pinned framework versions, the Elixir and OTP versions, the date and the
results. To revalidate a guide against a new framework release:

1. Create a scratch project outside the SigilGuard repository.
2. Add the framework pins from the guide's Dependencies section and SigilGuard
   as a path dependency or an unpacked Hex package.
3. Copy the guide's complete modules into the scratch project and exercise
   allowed structured values and every denial path.
4. Run `mix compile --warnings-as-errors`.
5. From the scratch project, run the repository's consumer checks against the
   compiled guide modules, with `SIGIL_GUIDE_TARGET` set to the guide's target
   from the table below:

   ```bash
   SIGIL_GUIDE_TARGET=jido mix run /path/to/sigil_guard/bin/guide_consumer.exs
   ```

6. Record the date, Elixir and OTP versions, resolved package versions and
   results in the guide's Compatibility section.

| Guide | `SIGIL_GUIDE_TARGET` | Additional checks |
|-------|----------------------|-------------------|
| Hermes MCP | `hermes`, then `anubis` | Add `plug` to validate the Plug placement. Repeat in a separate consumer with `anubis_mcp` and the Anubis component. |
| Jido | `jido` | None. |
| LangChain And ReqLLM | `llm` | None. The checks make no provider or remote model call. |
| Tidewave | `tidewave` | Exercise the shipped policy's read, write and eval decisions, scanner denials after a policy allow, mismatched tool identities and exact native value preservation. Confirm that Tidewave's public Plug rejects parsed bodies; this documents the unsupported insertion point and does not claim transport integration. |
