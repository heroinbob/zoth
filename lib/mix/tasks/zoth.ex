defmodule Mix.Tasks.Zoth do
  use Mix.Task

  @shortdoc "Prints Zoth help information"

  @moduledoc """
  Prints Zoth tasks and their information.
      mix zoth
  """

  @doc false
  def run(args) do
    case args do
      [] -> general()
      _ -> Mix.raise("Invalid arguments, expected: mix zoth")
    end
  end

  defp general do
    Application.ensure_all_started(:zoth)
    Mix.shell.info "Zoth v#{Application.spec(:zoth, :vsn)}"
    Mix.shell.info Application.spec(:zoth, :description)
    Mix.shell.info "\nAvailable tasks:\n"
    Mix.Tasks.Help.run(["--search", "zoth."])
  end
end
