defmodule Mix.Tasks.Zoth.Install do
  @shortdoc "Installs Zoth"

  @moduledoc """
  Generates migrations, schema module files, and updates config.

        mix zoth.install

        mix zoth.install --no-schemas

  ## Arguments

    * `--context-app` - context app to use for path and module names
    * `--no-migration` - don't create migration file
    * `--no-schemas` - don't create schema module files
  """

  use Mix.Task

  alias Zoth.Config, as: ProviderConfig
  alias Mix.{Ecto, Zoth, Zoth.Config}
  alias Mix.Tasks.Zoth.Gen.{Migration, Schemas}

  @switches     [context_app: :string, migration: :boolean, schemas: :boolean]
  @default_opts [migration: true, schemas: true]
  @mix_task     "zoth.install"

  @impl true
  def run(args) do
    Zoth.no_umbrella!(@mix_task)

    args
    |> Zoth.parse_options(@switches, @default_opts)
    |> parse()
    |> run_migration(args)
    |> run_schemas(args)
    |> print_config_instructions(args)
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp run_migration(%{migration: true} = config, args) do
    Migration.run(args)

    config
  end
  defp run_migration(config, _args), do: config

  defp run_schemas(%{schemas: true} = config, args) do
    Schemas.run(args)

    config
  end
  defp run_schemas(config, _args), do: config

  defp print_config_instructions(config, args) do
    [repo | _repos] = Ecto.parse_repo(args)
    context_app     = Map.get(config, :context_app) || Zoth.otp_app()
    resource_owner  = resource_owner(ProviderConfig.app_base(context_app))

    content = Config.gen(context_app, repo: inspect(repo), resource_owner: resource_owner)

    Mix.shell.info(
      """
      Zoth has been installed! Please append the following to `config/config.ex`:

      #{content}
      """)

    config
  end

  defp resource_owner(base), do: inspect Module.concat([base, "Users", "User"])
end
