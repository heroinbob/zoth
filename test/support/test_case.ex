defmodule Zoth.TestCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox

  setup do
    :ok = Sandbox.checkout(Dummy.Repo)
    Sandbox.mode(Dummy.Repo, {:shared, self()})

    :ok
  end
end
