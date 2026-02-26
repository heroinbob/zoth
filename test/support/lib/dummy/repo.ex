defmodule Dummy.Repo do
  @moduledoc false
  use Ecto.Repo, otp_app: :zoth, adapter: Ecto.Adapters.Postgres

  def log(_cmd), do: nil
end
