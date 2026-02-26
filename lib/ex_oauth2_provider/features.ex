defmodule Zoth.Features do
  @moduledoc """
  Determine the status of configurable features.
  """
  @behaviour Zoth.Behaviours.SkipAuthorization

  def skip_authorization?(_user, _application), do: false
end
