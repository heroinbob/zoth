defmodule Dummy.OauthAccessTokens.OauthAccessToken do
  @moduledoc false

  use Ecto.Schema
  use Zoth.AccessTokens.AccessToken, otp_app: :zoth

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_access_tokens" do
    access_token_fields()
    timestamps()
  end
end
