defmodule Mix.Tasks.Zoth.AddOpenIdFields do
  @shortdoc "Generate migration for adding all OpenID fields"

  @moduledoc """
  Generate a migration file that adds all the fields needed for the OpenID feature.

      # Generate the migration that updates the tables with default names.
      mix zoth.add_open_id_fields -r MyApp.Repo

      # Generate the migration with custom table name(s)
      mix zoth.add_open_id_post_logout_redirect_uri -r MyApp.Repo --apps-table some_other_name --grants-table yet_another_name

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  If you have an umbrella application then you must execute this within
  the target app directory. You can't execute this within an umbrella at
  the root.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--apps-table` - The name of the apps table to modify. Default is oauth_applications
    * `--grants-table` - The name of the grants table to modify. Default is oauth_access_grants
  """
  use Mix.Task

  import Mix.Tasks.Zoth.MigrationTask

  @context_name "AddOpenIdFields"

  @default_opts [
    apps_table: "oauth_applications",
    grants_table: "oauth_access_grants"
  ]

  @mix_task "zoth.add_open_id_fields"

  @switches [
    apps_table: :string,
    grants_table: :string
  ]

  @template """
  defmodule <%= inspect repo %>.Migrations.AddOpenIdFields do
    use Ecto.Migration

    def change do
      alter table(:<%= apps_table  %>) do
        add :open_id_post_logout_redirect_uri, :string
      end

      alter table(:<%= grants_table %>) do
        add :open_id_nonce, :string
      end

      create unique_index(:<%= grants_table %>, [:open_id_nonce])
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
