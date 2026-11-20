%{
  configs: [
    %{
      name: "default",
      files: %{
        included: [
          "lib/",
          "test/",
          "bench/",
          "bin/",
          "config/",
          "mix.exs",
          ".check.exs",
          ".credo.exs",
          ".doctor.exs",
          ".formatter.exs"
        ],
        excluded: [~r"/_build/", ~r"/deps/"]
      },
      plugins: [],
      requires: [],
      strict: true,
      parse_timeout: 5000,
      color: true,
      checks: %{
        enabled: [
          # ── Consistency ──────────────────────────────────
          {Credo.Check.Consistency.ExceptionNames, []},
          {Credo.Check.Consistency.LineEndings, [force: :unix]},
          {Credo.Check.Consistency.MultiAliasImportRequireUse, []},
          {Credo.Check.Consistency.ParameterPatternMatching, [force: :after]},
          {Credo.Check.Consistency.SpaceAroundOperators, [ignore: []]},
          {Credo.Check.Consistency.SpaceInParentheses, []},
          {Credo.Check.Consistency.TabsOrSpaces, [force: :spaces]},
          {Credo.Check.Consistency.UnusedVariableNames, [force: :anonymous]},

          # ── Design ───────────────────────────────────────
          {Credo.Check.Design.SkipTestWithoutComment, []},
          {Credo.Check.Design.TagFIXME, []},
          {Credo.Check.Design.TagTODO, []},

          # ── Readability ──────────────────────────────────
          # AliasAs — library code aliases a module under its own last name.
          # The listed modules collide with a standard library module or with
          # a sibling alias and need `:as`. Tests rename fixtures for
          # readability and are not checked.
          {Credo.Check.Readability.AliasAs,
           [
             ignore: [
               SigilGuard.Backend.Elixir,
               SigilGuard.BoundaryPolicy.File,
               SigilGuard.Runtime.Stream,
               SigilGuard.ToolGateway.Base,
               SigilGuard.RepoPolicy.Decision
             ],
             files: %{included: ["lib/"]}
           ]},
          {Credo.Check.Readability.AliasOrder, []},
          {Credo.Check.Readability.BlockPipe, []},
          {Credo.Check.Readability.FunctionNames, []},
          {Credo.Check.Readability.ImplTrue, []},
          {Credo.Check.Readability.LargeNumbers, []},
          {Credo.Check.Readability.MaxLineLength,
           [max_length: 100, ignore_definitions: false, ignore_urls: false]},
          {Credo.Check.Readability.ModuleAttributeNames, []},
          {Credo.Check.Readability.ModuleDoc, [ignore_names: [], ignore_modules_using: []]},
          {Credo.Check.Readability.ModuleNames, []},
          {Credo.Check.Readability.OneArityFunctionInPipe, []},
          {Credo.Check.Readability.OnePipePerLine, []},
          {Credo.Check.Readability.ParenthesesInCondition, []},
          {Credo.Check.Readability.ParenthesesOnZeroArityDefs, []},
          {Credo.Check.Readability.PipeIntoAnonymousFunctions, []},
          {Credo.Check.Readability.PredicateFunctionNames, []},
          # PreferUnquotedAtoms — incompatible with Elixir >= 1.7.0
          {Credo.Check.Readability.PreferUnquotedAtoms, false},
          {Credo.Check.Readability.RedundantBlankLines, []},
          {Credo.Check.Readability.Semicolons, []},
          {Credo.Check.Readability.SeparateAliasRequire, []},
          {Credo.Check.Readability.SingleFunctionToBlockPipe, []},
          {Credo.Check.Readability.SpaceAfterCommas, []},
          {Credo.Check.Readability.Specs, []},
          {Credo.Check.Readability.StrictModuleLayout,
           [
             order:
               ~w(shortdoc moduledoc behaviour use import alias require opaque type typep
                  defstruct callback macrocallback optional_callbacks)a,
             ignore: ~w(module_attribute module)a
           ]},
          {Credo.Check.Readability.StringSigils, [maximum_allowed_quotes: 2]},
          {Credo.Check.Readability.TrailingBlankLine, []},
          {Credo.Check.Readability.TrailingWhiteSpace, [ignore_strings: false]},
          {Credo.Check.Readability.UnnecessaryAliasExpansion, []},
          {Credo.Check.Readability.VariableNames, []},
          {Credo.Check.Readability.WithCustomTaggedTuple, []},
          {Credo.Check.Readability.WithSingleClause, []},

          # ── Refactor ─────────────────────────────────────
          {Credo.Check.Refactor.AppendSingleItem, []},
          {Credo.Check.Refactor.Apply, []},
          {Credo.Check.Refactor.CaseTrivialMatches, []},
          {Credo.Check.Refactor.CondStatements, []},
          {Credo.Check.Refactor.CyclomaticComplexity, [max_complexity: 9]},
          {Credo.Check.Refactor.DoubleBooleanNegation, []},
          {Credo.Check.Refactor.FilterCount, []},
          {Credo.Check.Refactor.FilterFilter, []},
          {Credo.Check.Refactor.FilterReject, []},
          {Credo.Check.Refactor.FunctionArity, [max_arity: 5]},
          {Credo.Check.Refactor.IoPuts, []},
          {Credo.Check.Refactor.LongQuoteBlocks, [max_line_count: 18]},
          # MapInto — incompatible with Elixir >= 1.8.0
          {Credo.Check.Refactor.MapInto, false},
          {Credo.Check.Refactor.MapJoin, []},
          {Credo.Check.Refactor.MapMap, []},
          {Credo.Check.Refactor.MatchInCondition, []},
          {Credo.Check.Refactor.NegatedConditionsInUnless, []},
          {Credo.Check.Refactor.NegatedConditionsWithElse, []},
          {Credo.Check.Refactor.NegatedIsNil, []},
          {Credo.Check.Refactor.Nesting, [max_nesting: 2]},
          {Credo.Check.Refactor.PassAsyncInTestCases, []},
          {Credo.Check.Refactor.PerceivedComplexity, [max_complexity: 9]},
          {Credo.Check.Refactor.RedundantWithClauseResult, []},
          {Credo.Check.Refactor.RejectFilter, []},
          {Credo.Check.Refactor.RejectReject, []},
          {Credo.Check.Refactor.UnlessWithElse, []},
          {Credo.Check.Refactor.UtcNowTruncate, []},
          {Credo.Check.Refactor.WithClauses, []},

          # ── Warning ──────────────────────────────────────
          {Credo.Check.Warning.ApplicationConfigInModuleAttribute, []},
          {Credo.Check.Warning.BoolOperationOnSameValues, []},
          {Credo.Check.Warning.Dbg, []},
          # Library code runs inside a host release, where Mix and IEx are
          # absent, and it starts no ports or distribution of its own.
          {Credo.Check.Warning.ForbiddenModule,
           [
             modules: [Mix, IEx, Port, Node],
             files: %{included: ["lib/sigil_guard.ex", "lib/sigil_guard/"]}
           ]},
          {Credo.Check.Warning.IExPry, []},
          {Credo.Check.Warning.IoInspect, []},
          # LazyLogging — incompatible with Elixir >= 1.7.0
          {Credo.Check.Warning.LazyLogging, false},
          {Credo.Check.Warning.LeakyEnvironment, []},
          {Credo.Check.Warning.MapGetUnsafePass, []},
          {Credo.Check.Warning.MissedMetadataKeyInLoggerConfig, []},
          {Credo.Check.Warning.MixEnv, []},
          {Credo.Check.Warning.OperationOnSameValues, []},
          {Credo.Check.Warning.OperationWithConstantResult, []},
          {Credo.Check.Warning.RaiseInsideRescue, []},
          {Credo.Check.Warning.SpecWithStruct, []},
          {Credo.Check.Warning.UnsafeExec, []},
          {Credo.Check.Warning.UnsafeToAtom, []},
          {Credo.Check.Warning.UnusedEnumOperation, []},
          {Credo.Check.Warning.UnusedFileOperation, []},
          {Credo.Check.Warning.UnusedKeywordOperation, []},
          {Credo.Check.Warning.UnusedListOperation, []},
          {Credo.Check.Warning.UnusedMapOperation, []},
          {Credo.Check.Warning.UnusedPathOperation, []},
          {Credo.Check.Warning.UnusedRegexOperation, []},
          {Credo.Check.Warning.UnusedStringOperation, []},
          {Credo.Check.Warning.UnusedTupleOperation, []},
          {Credo.Check.Warning.WrongTestFileExtension, []},
          {Credo.Check.Warning.WrongTestFilename, []},

          # ── Enabled with a measured bound ────────────────
          # Each bound is the largest value in the tree when it was set, so
          # the check passes today and fails when the code gets worse. Lower
          # a bound when a refactor allows it; do not raise one.
          # AliasUsage — a module nested three deep and used three times in a
          # file gets an alias. Single-use references are not flagged.
          {Credo.Check.Design.AliasUsage,
           [if_nested_deeper_than: 2, if_called_more_often_than: 2]},
          {Credo.Check.Design.DuplicatedCode, [mass_threshold: 64]},
          {Credo.Check.Readability.NestedFunctionCalls, [min_pipeline_length: 4]},
          {Credo.Check.Refactor.ABCSize, [max_size: 82, files: %{included: ["lib/"]}]},
          {Credo.Check.Refactor.ModuleDependencies,
           [max_deps: 26, files: %{included: ["lib/"]}]},
          # CapabilityManifest has 33 fields and is a consumer contract.
          {Credo.Check.Warning.StructFieldAmount, [max_fields: 33]},
          # ExpensiveEmptyEnumCheck — `length(list) == 0` walks the list.
          # Tests may prefer it for clarity and are not checked.
          {Credo.Check.Warning.ExpensiveEmptyEnumCheck, [files: %{included: ["lib/"]}]},

          # ── Disabled (with reason) ───────────────────────
          # MultiAlias — multi-alias grouping is fine
          {Credo.Check.Readability.MultiAlias, false},
          # PipeChainStart — Regex/Enum results commonly piped
          {Credo.Check.Refactor.PipeChainStart, false},
          # PreferImplicitTry — explicit try clearer in security code
          {Credo.Check.Readability.PreferImplicitTry, false},
          # SinglePipe — x |> Func.call() is common and readable
          {Credo.Check.Readability.SinglePipe, false},
          # VariableRebinding — rebinding is idiomatic Elixir
          {Credo.Check.Refactor.VariableRebinding, false}
        ]
      }
    }
  ]
}
