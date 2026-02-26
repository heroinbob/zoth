defmodule Zoth.ApplicationsTest do
  use Zoth.TestCase

  alias Zoth.Test.Fixtures
  alias Zoth.{AccessTokens, Applications}
  alias Dummy.{OauthApplications.OauthApplication, OauthAccessTokens.OauthAccessToken, Repo}

  @valid_attrs %{name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs %{}

  setup do
    {:ok, %{user: Fixtures.insert(:user)}}
  end

  test "get_applications_for/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert {:ok, _application} =
             Applications.create_application(
               Fixtures.insert(:user),
               @valid_attrs,
               otp_app: :zoth
             )

    assert [%OauthApplication{id: id}] =
             Applications.get_applications_for(user, otp_app: :zoth)

    assert id == application.id
  end

  test "get_application!/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert %OauthApplication{id: id} =
             Applications.get_application!(application.uid, otp_app: :zoth)

    assert id == application.id
  end

  test "get_application/2", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert %OauthApplication{id: id} =
             Applications.get_application(application.uid, otp_app: :zoth)

    assert id == application.id
  end

  test "get_application_for!/2", %{user: user} do
    {:ok, application} =
      Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert %OauthApplication{id: id} =
             Applications.get_application_for!(user, application.uid,
               otp_app: :zoth
             )

    assert id == application.id

    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application_for!(
        Fixtures.insert(:user),
        application.uid,
        otp_app: :zoth
      )
    end
  end

  test "get_authorized_applications_for/2", %{user: user} do
    application = Fixtures.insert(:application)
    application2 = Fixtures.insert(:application, uid: "newapp")

    assert {:ok, token} =
             AccessTokens.create_token(user, %{application: application},
               otp_app: :zoth
             )

    assert {:ok, _token} =
             AccessTokens.create_token(user, %{application: application2},
               otp_app: :zoth
             )

    assert user
           |> Applications.get_authorized_applications_for(otp_app: :zoth)
           |> Enum.map(& &1.id) ==
             [application.id, application2.id]

    assert Applications.get_authorized_applications_for(
             Fixtures.insert(:user),
             otp_app: :zoth
           ) == []

    AccessTokens.revoke(token, otp_app: :zoth)

    assert user
           |> Applications.get_authorized_applications_for(otp_app: :zoth)
           |> Enum.map(& &1.id) == [application2.id]
  end

  describe "create_application/3" do
    test "with valid attributes", %{user: user} do
      assert {:ok, application} =
               Applications.create_application(user, @valid_attrs, otp_app: :zoth)

      assert application.name == @valid_attrs.name
      assert application.scopes == "public"
    end

    test "with invalid attributes", %{user: user} do
      assert {:error, changeset} =
               Applications.create_application(user, @invalid_attrs, otp_app: :zoth)

      assert changeset.errors[:name]
    end

    test "with invalid scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

      assert {:error, %Ecto.Changeset{}} =
               Applications.create_application(user, attrs, otp_app: :zoth)
    end

    test "with limited scopes", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "read write"})

      assert {:ok, application} =
               Applications.create_application(user, attrs, otp_app: :zoth)

      assert application.scopes == "read write"
    end

    test "adds random secret", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, @valid_attrs, otp_app: :zoth)

      {:ok, application2} =
        Applications.create_application(user, @valid_attrs, otp_app: :zoth)

      assert application.secret != application2.secret
    end

    test "permits empty string secret", %{user: user} do
      attrs = Map.merge(@valid_attrs, %{secret: ""})

      assert {:ok, application} =
               Applications.create_application(user, attrs, otp_app: :zoth)

      assert application.secret == ""
    end

    test "adds random uid", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, @valid_attrs, otp_app: :zoth)

      {:ok, application2} =
        Applications.create_application(user, @valid_attrs, otp_app: :zoth)

      assert application.uid != application2.uid
    end

    test "adds custom uid", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, Map.merge(@valid_attrs, %{uid: "custom"}),
          otp_app: :zoth
        )

      assert application.uid == "custom"
    end

    test "adds custom secret", %{user: user} do
      {:ok, application} =
        Applications.create_application(user, Map.merge(@valid_attrs, %{secret: "custom"}),
          otp_app: :zoth
        )

      assert application.secret == "custom"
    end
  end

  test "update_application/3", %{user: user} do
    assert {:ok, application} =
             Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert {:ok, application} =
             Applications.update_application(application, %{name: "Updated App"},
               otp_app: :zoth
             )

    assert application.name == "Updated App"
  end

  test "delete_application/2", %{user: user} do
    {:ok, application} =
      Applications.create_application(user, @valid_attrs, otp_app: :zoth)

    assert {:ok, _appliction} =
             Applications.delete_application(application, otp_app: :zoth)

    assert_raise Ecto.NoResultsError, fn ->
      Applications.get_application!(application.uid, otp_app: :zoth)
    end
  end

  test "revoke_all_access_tokens_for/3", %{user: user} do
    application = Fixtures.insert(:application)

    {:ok, token} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :zoth)

    {:ok, token2} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :zoth)

    {:ok, token3} =
      AccessTokens.create_token(user, %{application: application}, otp_app: :zoth)

    AccessTokens.revoke(token3)

    assert {:ok, objects} =
             Applications.revoke_all_access_tokens_for(application, user,
               otp_app: :zoth
             )

    assert Enum.count(objects) == 2

    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token.id))
    assert AccessTokens.is_revoked?(Repo.get!(OauthAccessToken, token2.id))
  end
end
