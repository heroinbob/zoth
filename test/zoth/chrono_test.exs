defmodule Zoth.ChronoTest do
  use ExUnit.Case, async: true

  alias Zoth.Chrono

  describe "add_time/2" do
    test "adds seconds to a given DateTime struct" do
      assert Chrono.add_time(~U[2026-01-14 16:53:00Z], 42) == ~U[2026-01-14 16:53:42Z]
    end

    test "adds seconds to a given NaiveDateTime struct" do
      assert Chrono.add_time(~N[2026-01-14 16:53:00Z], 42) == ~N[2026-01-14 16:53:42Z]
    end
  end

  describe "add_time/3" do
    test "adds the given unit to a given struct" do
      assert Chrono.add_time(~U[2026-01-14 16:53:00Z], 1, :hour) == ~U[2026-01-14 17:53:00Z]
    end
  end

  describe "expired?/2" do
    test "returns true when the given value + TTL is in the future" do
      value = DateTime.add(DateTime.utc_now(), -5, :second)

      for ttl <- 1..4 do
        result = Chrono.expired?(value, ttl)

        assert result == false, "expected ttl #{ttl} to cause a false response but got #{result}"
      end

      # A 2 second window is plenty accurate for our test purposes.
      assert Chrono.expired?(value, 7) == true
    end

    test "supports NaiveDateTime structs" do
      value = NaiveDateTime.add(NaiveDateTime.utc_now(), -5, :second)

      for ttl <- 1..4 do
        result = Chrono.expired?(value, ttl)

        assert result == false, "expected ttl #{ttl} to cause a false response but got #{result}"
      end

      # A 2 second window is plenty accurate for our test purposes.
      assert Chrono.expired?(value, 7) == true
    end
  end

  describe "to_unix/2" do
    test "converts a DateTime struct" do
      assert Chrono.to_unix(~U[2026-01-14 16:53:00Z]) == 1_768_409_580
    end

    test "converts a NaiveDateTime struct" do
      assert Chrono.to_unix(~N[2026-01-14 16:53:00Z]) == 1_768_409_580
    end
  end

  describe "unix_now/0" do
    test "returns now as a unix time" do
      # Give it a short range to prevent flakyness.
      base = DateTime.to_unix(DateTime.utc_now())
      assert Chrono.unix_now() in base..(base + 2)
    end
  end
end
