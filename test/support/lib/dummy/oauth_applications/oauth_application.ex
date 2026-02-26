defmodule Dummy.OauthApplications.OauthApplication do
  @moduledoc false

  use Ecto.Schema
  use Zoth.Applications.Application, otp_app: :zoth

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_applications" do
    application_fields()
    timestamps()
  end
end
