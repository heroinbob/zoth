defmodule Mix.Tasks.Zoth.AddPkceFields do
  @shortdoc "Generates migration for adding PKCE fields"

  @moduledoc """
  Generates a migration file that adds the PKCE columns to AccessGrants.

      # Update the default tables
      mix zoth.add_pkce_fields -r MyApp.Repo

      # Update the tables with custom names
      mix zoth.add_pkce_fields -r MyApp.Repo --apps-table some_other_name --grants-table another_name

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--apps-table` - The name of the apps table
    * `--grants-table` - The name of the grants table
  """
  use Mix.Task

  import Mix.Tasks.Zoth.MigrationTask

  @context_name "AddPkceFields"

  @switches [
    apps_table: :string,
    grants_table: :string
  ]

  @default_opts [
    apps_table: "oauth_applications",
    grants_table: "oauth_access_grants"
  ]

  @mix_task "zoth.add_pkce_fields"

  @template """
  defmodule <%= inspect repo %>.Migrations.AddPkceFields do
    use Ecto.Migration

    def change do
      alter table(:<%= apps_table %>) do
        add :pkce, :string, null: false, default: "disabled"
      end

      alter table(:<%= grants_table %>) do
        add :code_challenge, :string
        add :code_challenge_method, :string
      end

      create unique_index(:<%= grants_table %>, [:code_challenge])
    end
  end
  """

  @impl true
  def run(args) do
    disallow_in_umbrella!(@mix_task)
    params = parse_args(args, @switches, @default_opts)
    assigns = params |> Map.take([:apps_table, :grants_table]) |> Enum.map(& &1)

    create_migration_file(%{
      assigns: assigns,
      command_line_args: args,
      context_name: @context_name,
      template: @template
    })
  end
end
