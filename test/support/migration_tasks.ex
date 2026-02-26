defmodule Zoth.Test.MigrationTasks do
  defmacro __using__(_opts) do
    quote do
      import Zoth.Test.MigrationTasks

      @tmp_path Path.join(~w[tmp zoth])
      @migrations_path Path.join(@tmp_path, "migrations")

      def clear_migrations! do
        File.rm_rf!(@tmp_path)
        File.mkdir_p!(@tmp_path)
      end

      def get_migration_filename! do
        @migrations_path |> File.ls!() |> hd()
      end

      def get_migration_content! do
        filename = get_migration_filename!()
        @migrations_path |> Path.join(filename) |> File.read!()
      end
    end
  end
end
