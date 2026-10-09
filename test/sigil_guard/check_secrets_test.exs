defmodule SigilGuard.CheckSecretsTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @script Path.expand("../../bin/check-secrets", __DIR__)
  @checksum "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

  setup do
    root = Path.join(System.tmp_dir!(), "sigil-scanner-#{System.unique_integer([:positive])}")
    bin = Path.join(root, "bin")
    File.mkdir_p!(bin)
    on_exit(fn -> File.rm_rf!(root) end)

    for command <- ~w(mktemp cut rm cp chmod) do
      File.ln_s!(System.find_executable(command), Path.join(bin, command))
    end

    executable(bin, "uname", "case \"$1\" in -s) printf Linux ;; -m) printf x86_64 ;; esac")
    executable(bin, "sha256sum", "printf '%s  %s\\n' '#{@checksum}' \"$1\"")

    executable(bin, "curl", ~S"""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --output ]; then
        shift
        printf 'fixture archive' > "$1"
      fi
      shift
    done
    printf 'fixture download\n'
    """)

    executable(bin, "tar", ~S"""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = -C ]; then
        shift
        cp "${SCANNER_FIXTURE}" "$1/gitleaks"
        chmod +x "$1/gitleaks"
      fi
      shift
    done
    """)

    scanner =
      executable(root, "scanner", ~S"""
      for argument do printf '<%s>' "$argument"; done
      printf '\n'
      exit "${SCANNER_STATUS}"
      """)

    {:ok, root: root, bin: bin, scanner: scanner}
  end

  test "downloaded scanner cleans temporary files after success and failure", context do
    for status <- [0, 7] do
      {output, actual_status, temporary_files} = scan(context, status)

      assert output == "fixture download\n<git><--no-banner><--redact><.>\n"
      assert actual_status == status
      assert temporary_files == []
    end
  end

  test "installed scanner retains its exit status without downloading", context do
    File.ln_s!(context.scanner, Path.join(context.bin, "gitleaks"))

    for status <- [0, 7] do
      {output, actual_status, temporary_files} = scan(context, status)

      assert output == "<git><--no-banner><--redact><.>\n"
      assert actual_status == status
      assert temporary_files == []
    end
  end

  defp scan(context, status) do
    temporary = Path.join(context.root, "temporary-#{status}")
    File.mkdir_p!(temporary)

    {output, actual_status} =
      System.cmd("/bin/sh", [@script],
        env: [
          {"PATH", context.bin},
          {"TMPDIR", temporary},
          {"SCANNER_FIXTURE", context.scanner},
          {"SCANNER_STATUS", Integer.to_string(status)}
        ],
        stderr_to_stdout: true
      )

    {output, actual_status, File.ls!(temporary)}
  end

  defp executable(directory, name, body) do
    path = Path.join(directory, name)
    File.write!(path, "#!/bin/sh\nset -eu\n" <> body <> "\n")
    File.chmod!(path, 0o755)
    path
  end
end
