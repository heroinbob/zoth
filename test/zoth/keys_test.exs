defmodule Zoth.KeysTest do
  use ExUnit.Case
  alias Zoth.Keys

  test "access_token/1" do
    assert Keys.access_token_key(:foo) == :zoth_foo_access_token
  end

  test "base_key/1" do
    assert Keys.base_key(:foo) == :zoth_foo
  end

  test "base_key/1 beginning with zoth_" do
    assert Keys.base_key("zoth_foo") == :zoth_foo
  end
end
