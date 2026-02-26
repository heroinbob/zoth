defmodule Zoth.Test.Mix.MigrationRepo do
  @moduledoc """
  Basic context to simulate a repo for testing migrations with.
  """
  def __adapter__, do: true

  def config,
    do: [
      priv: "tmp/zoth",
      otp_app: :zoth
    ]
end
