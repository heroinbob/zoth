defmodule Zoth.Authorization.DeviceCodeTest do
  use Zoth.TestCase

  alias Dummy.OauthDeviceGrants.OauthDeviceGrant
  alias Zoth.Authorization
  alias Zoth.Test.Fixtures

  @config [otp_app: :zoth]

  setup do
    application =
      Fixtures.insert(
        :application,
        uid: "abc123",
        scopes: "app:read app:write"
      )

    {:ok, %{application: application}}
  end

  describe "#authorize/3" do
    test "invokes the user interaction and approves the device grant" do
      device_grant = Fixtures.insert(:device_grant)
      owner = Fixtures.insert(:user)

      request = %{
        "response_type" => "device_code",
        "user_code" => device_grant.user_code
      }

      {:ok, %OauthDeviceGrant{}} = Authorization.authorize(owner, request, @config)
    end
  end

  describe "#preauthorize_device/2" do
    test "invokes the device authorization and creats the device grant", context do
      %{application: application} = context

      request = %{"client_id" => application.uid}

      {:ok,
       %{
         device_code: _device_code,
         expires_in: _expires_in,
         interval: _interval,
         user_code: _user_code,
         verification_uri: _verification_uri
       }} = Authorization.preauthorize_device(request, @config)
    end
  end
end
