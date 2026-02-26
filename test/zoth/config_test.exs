defmodule Zoth.ConfigTest do
  # Do not use async in here. Some tests make config changes.
  use ExUnit.Case
  use Zoth.Test.ConfigChanges

  alias Zoth.Config

  test "repo/1" do
    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:zoth, Zoth)
    Application.put_env(:my_app, Zoth, repo: Dummy.Repo)

    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:my_app, Zoth)

    assert_raise RuntimeError, ~r/config :my_app, Zoth/, fn ->
      Config.repo(otp_app: :my_app)
    end

    assert_raise RuntimeError, ~r/config :zoth, Zoth/, fn ->
      Config.repo([])
    end
  end

  describe "pkce_setting/1" do
    test "returns :disabled by default" do
      assert Config.pkce_setting([]) == :disabled
    end

    test "returns the value from the given config when supported" do
      for value <- [:all_methods, :disabled, :plain_only, :s256_only] do
        assert Config.pkce_setting(pkce: value) == value
      end
    end

    test "returns the value from the app config when supported" do
      for value <- [:all_methods, :disabled, :plain_only, :s256_only] do
        Application.put_env(:my_app, Zoth, pkce: value)

        assert Config.pkce_setting(otp_app: :my_app) == value
      end
    end

    test "raises an error when given an unsupported value" do
      assert_raise ArgumentError,
                   "pkce must be one of all_methods | disabled | plain_only | s256_only",
                   fn ->
                     assert Config.pkce_setting(pkce: :foo)
                   end

      assert_raise ArgumentError,
                   "pkce must be one of all_methods | disabled | plain_only | s256_only",
                   fn ->
                     Application.put_env(:my_app, Zoth, pkce: :foo)

                     assert Config.pkce_setting(otp_app: :my_app)
                   end
    end
  end

  describe "use_pkce?/1" do
    test "returns true when the otp app is set to use_pkce" do
      config = [otp_app: :zoth]
      assert Config.use_pkce?(pkce: :all_methods) == true
      assert Config.use_pkce?(pkce: :plain_only) == true
      assert Config.use_pkce?(pkce: :s256_only) == true
      assert Config.use_pkce?(pkce: :disabled) == false
      assert Config.use_pkce?(config) == false

      # Verify it grabs from the app env
      Application.put_env(:my_app, Zoth, pkce: :all_methods)
      assert Config.use_pkce?(otp_app: :my_app) == true

      Application.put_env(:my_app, Zoth, pkce: :disabled)
      assert Config.use_pkce?(otp_app: :my_app) == false
    end
  end
end
