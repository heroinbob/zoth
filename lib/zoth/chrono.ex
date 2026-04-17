defmodule Zoth.Chrono do
  @moduledoc """
  Help to support manipulating several kinds of date/time structs.
  """

  @type any_date_time :: DateTime.t() | NaiveDateTime.t()

  @supported_types [DateTime, NaiveDateTime]
  @unix_epoch ~N[1970-01-01 00:00:00]

  @spec add_time(any_date_time(), integer()) :: any_date_time()
  @spec add_time(any_date_time(), atom()) :: any_date_time()
  def add_time(date_time, amount, unit \\ :second)

  def add_time(%DateTime{} = value, amount, unit) do
    DateTime.add(value, amount, unit)
  end

  def add_time(%NaiveDateTime{} = value, amount, unit) do
    NaiveDateTime.add(value, amount, unit)
  end

  @doc """
  Compare two values and returns :lt if a is earlier than b.
  """
  @spec compare(a :: any_date_time(), b :: any_date_time()) :: :lt | :gt | :eq
  def compare(%mod{} = a, b) when mod in @supported_types do
    mod.compare(a, b)
  end

  @doc """
  Determine if the given value has expired. TTL is in seconds.

  ## Options

  * `:relative_to` - Default is UTC now. When specified this is the value that
                     the given value is compared to.
  """
  @spec expired?(value :: any_date_time(), ttl :: integer()) :: boolean()

  @spec expired?(
          value :: any_date_time(),
          ttl :: integer(),
          opts :: keyword()
        ) :: boolean()
  def expired?(%mod{} = value, ttl, opts \\ []) when mod in @supported_types do
    nowish = Keyword.get(opts, :relative_to, mod.utc_now())
    max_age = add_time(value, ttl)

    compare(max_age, nowish) == :gt
  end

  @spec to_unix(DateTime.t() | NaiveDateTime.t()) :: non_neg_integer()
  def to_unix(%DateTime{} = value) do
    DateTime.to_unix(value)
  end

  def to_unix(%NaiveDateTime{} = value) do
    NaiveDateTime.diff(value, @unix_epoch)
  end

  @spec unix_now() :: non_neg_integer()
  def unix_now do
    to_unix(DateTime.utc_now())
  end
end
