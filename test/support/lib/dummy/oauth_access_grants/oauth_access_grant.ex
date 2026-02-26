defmodule Dummy.OauthAccessGrants.OauthAccessGrant do
  @moduledoc false

  use Ecto.Schema
  use Zoth.AccessGrants.AccessGrant, otp_app: :zoth

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_access_grants" do
    access_grant_fields()
    timestamps()
  end
end
