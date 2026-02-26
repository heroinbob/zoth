defmodule Zoth.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that the request has been authenticated with an access token.

  If one is not found, the `unauthenticated/2` function is invoked with the
  `Plug.Conn.t` object and its params.

  ## Example

      # Will call the unauthenticated/2 function on your handler
      plug Zoth.Plug.EnsureAuthenticated, handler: SomeModule

      # look in the :secret location.  You can also do simple claim checks:
      plug Zoth.Plug.EnsureAuthenticated, handler: SomeModule, key: :secret

      plug Zoth.Plug.EnsureAuthenticated, handler: SomeModule, typ: "access"

  If the handler option is not passed, `Zoth.Plug.ErrorHandler` will provide
  the default behavior.
  """
  alias Plug.Conn
  alias Zoth.Plug

  @doc false
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @doc false
  @spec call(Conn.t(), keyword()) :: map()
  def call(conn, opts) do
    key = Keyword.get(opts, :key, :default)

    conn
    |> Plug.get_current_access_token(key)
    |> handle_authentication(conn, opts)
  end

  defp handle_authentication({:ok, _}, conn, _opts), do: conn
  defp handle_authentication({:error, reason}, %{params: params} = conn, opts) do
    params = Map.put(params, :reason, reason)
    module = Keyword.get(opts, :handler, Zoth.Plug.ErrorHandler)

    conn
    |> Conn.assign(:zoth_failure, reason)
    |> Conn.halt()
    |> module.unauthenticated(params)
  end
end
