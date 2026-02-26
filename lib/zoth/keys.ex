defmodule Zoth.Keys do
  @moduledoc false

  @doc false
  @spec access_token_key(atom()) :: atom()
  def access_token_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_access_token")
  end

  @doc false
  @spec base_key(binary()) :: atom()
  def base_key("zoth_" <> _ = the_key) do
    String.to_atom(the_key)
  end

  @doc false
  @spec base_key(atom()) :: atom()
  def base_key(the_key) do
    String.to_atom("zoth_#{the_key}")
  end
end
