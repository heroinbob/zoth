defmodule Zoth.Mixfile do
  use Mix.Project

  @version "1.0.0"

  def project do
    [
      app: :zoth,
      version: @version,
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: [
        list_unused_filters: true,
        plt_add_apps: [:ex_unit, :mix],
        plt_file: {:no_warn, "plts/zoth.plt"}
      ],

      # Hex
      description: "Elixir library for OAuth and OpenID providers",
      package: package(),

      # Docs
      name: "Zoth",
      docs: docs()
    ]
  end

  def application do
    [extra_applications: extra_applications(Mix.env())]
  end

  defp extra_applications(:test), do: [:ecto, :logger]
  defp extra_applications(_), do: [:logger]

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto, "~> 3.8"},
      {:jose, "~> 1.11"},
      {:plug, ">= 1.5.0 and < 2.0.0"},

      # Dev and test dependencies
      {:credo, "~> 1.7", only: [:dev, :test]},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:ex_machina, "~> 2.8.0", only: :test},
      {:ecto_sql, "~> 3.13", only: [:dev, :test]},
      {:plug_cowboy, "~> 2.7", only: :test},
      {:postgrex, "~> 0.21", only: :test}
    ]
  end

  defp package do
    [
      maintainers: ["Jeff McKenzie"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/heroinbob/zoth"},
      files: ~w(lib LICENSE mix.exs README.md)
    ]
  end

  defp docs do
    [
      source_ref: "v#{@version}",
      main: "Zoth",
      canonical: "http://hexdocs.pm/zoth",
      source_url: "https://github.com/heroinbob/zoth",
      extras: ["README.md"]
    ]
  end
end
