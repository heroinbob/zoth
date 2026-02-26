defmodule Mix.Zoth.Config do
  @moduledoc false

  @template """
  config :<%= app %>, <%= inspect key %><%= for {key, value} <- opts do %>,
    <%= key %>: <%= value %><% end %>
  """

  @spec gen(binary() | atom(), keyword()) :: binary()
  def gen(context_app, opts), do: EEx.eval_string(@template, app: context_app, key: Zoth, opts: opts)
end
