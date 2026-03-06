defmodule Mix.Tasks.Zoth.MigrationTask do
  alias Mix.{
    Ecto,
    Zoth,
    Zoth.Migration
  }

  @doc """
  Create a migration file.

  ## Attributes

  * `:command_line_args` - Required. The raw mix command line args.
  * `:context_name` - Required. The name of the migration context/module
  * `:template` - Required. The string template to generate the file using.
  * `:assigns` - Optional. The assigns to use in the template.
  """
  def create_migration_file(
        %{
          command_line_args: args,
          context_name: context_name,
          template: template
        } = attrs
      ) do
    repo = get_repo(args)
    assigns = Map.get(attrs, :assigns, [])

    assigns =
      Enum.reduce(
        [repo: repo],
        assigns,
        &[&1 | &2]
      )

    content = EEx.eval_string(template, assigns)
    Migration.create_migration_file(repo, context_name, content)
  end

  def disallow_in_umbrella!(mix_task) do
    Zoth.no_umbrella!(mix_task)
  end

  defp get_repo(command_line_args) do
    command_line_args
    |> Ecto.parse_repo()
    |> hd()
    |> Ecto.ensure_repo(command_line_args ++ ~w(--no-deps-check))
  end

  def parse_args(args, switches, defaults) do
    args |> Zoth.parse_options(switches, defaults) |> elem(0)
  end
end
