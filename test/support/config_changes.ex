defmodule Zoth.Test.ConfigChanges do
  alias Zoth.Test.OpenId

  defmacro __using__(_opts) do
    quote do
      import Zoth.Test.ConfigChanges

      setup do
        config = Application.get_env(:zoth, Zoth)

        on_exit(fn ->
          Application.put_env(:zoth, Zoth, config)
        end)
      end
    end
  end

  @doc """
  Replace the current config with the given changes.
  """
  def put_env_change(changes, app \\ :zoth, key \\ Zoth)
      when is_list(changes) do
    original = Application.get_env(app, key)

    changed =
      Enum.reduce(
        changes,
        original,
        fn {k, v}, acc ->
          Keyword.put(acc, k, v)
        end
      )

    Application.put_env(app, key, changed)
  end

  @doc """
  Replace values in the existing OpenId config. This allows you to change the open ID
  config but also retain what already is configured.
  """
  def add_open_id_changes(changes, app \\ :zoth, key \\ Zoth) do
    original = OpenId.get_app_config()
    changed = Map.merge(original, changes)

    put_env_change([open_id: changed], app, key)
  end
end
