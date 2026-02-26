defmodule Mix.Tasks.Zoth.Gen.Schemas do
  @shortdoc "Generates Zoth schema files"

  @moduledoc """
  Generates schema files.

      mix zoth.gen.schemas

      mix zoth.gen.schemas --binary-id --namespace oauth2

  ## Arguments

    * `--binary-id` - use binary id for primary keys
    * `--context-app` - context app to use for path and module names
    * `--device-code` - generate an optional schema for device code grants
    * `--namespace` - namespace to prepend table and schema module name
  """
  use Mix.Task

  alias Mix.{Zoth, Zoth.Schema}

  @switches [
    binary_id: :boolean,
    context_app: :string,
    device_code: :boolean,
    namespace: :string
  ]
  @default_opts [binary_id: false, device_code: false, namespace: "oauth"]
  @mix_task "zoth.gen.migrations"

  @impl true
  def run(args) do
    Zoth.no_umbrella!(@mix_task)

    args
    |> Zoth.parse_options(@switches, @default_opts)
    |> parse()
    |> create_schema_files()
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp create_schema_files(
         %{
           binary_id: binary_id,
           device_code: device_code,
           namespace: namespace
         } = config
       ) do
    context_app =
      Map.get(
        config,
        :context_app,
        Zoth.otp_app()
      )

    Schema.create_schema_files(
      context_app,
      namespace,
      binary_id: binary_id,
      device_code: device_code
    )
  end
end
