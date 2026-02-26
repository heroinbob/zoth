defmodule Mix.Tasks.ZothTest do
  use Zoth.Mix.TestCase

  alias Mix.Tasks.Zoth

  test "provide a list of available zoth mix tasks" do
    Zoth.run([])

    assert_received {:mix_shell, :info, ["Zoth v" <> _]}
    assert_received {:mix_shell, :info, ["mix zoth.install" <> _]}
  end

  test "expects no arguments" do
    assert_raise Mix.Error, fn ->
      Zoth.run(["invalid"])
    end
  end
end
