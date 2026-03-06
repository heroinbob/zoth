defmodule Mix.Tasks.Zoth.AddOpenIdFieldsTest do
  use Zoth.Mix.TestCase
  use Zoth.Test.MigrationTasks

  alias Zoth.Test.Mix.MigrationRepo
  alias Mix.Tasks.Zoth.AddOpenIdFields

  @options ~w(--repo #{inspect(MigrationRepo)})

  setup do
    clear_migrations!()
    :ok
  end

  describe "run/1" do
    test "generates the migration file with the correct content" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdFields.run(@options)

        assert filename = get_migration_filename!()
        assert String.match?(filename, ~r/^\d{14}_add_open_id_fields\.exs$/)

        assert get_migration_content!() ==
                 """
                 defmodule #{inspect(MigrationRepo)}.Migrations.AddOpenIdFields do
                   use Ecto.Migration

                   def change do
                     alter table(:oauth_applications) do
                       add :open_id_post_logout_redirect_uri, :string
                     end

                     alter table(:oauth_access_grants) do
                       add :open_id_nonce, :string
                     end

                     create unique_index(:oauth_access_grants, [:open_id_nonce])
                   end
                 end
                 """
      end)
    end

    test "supports setting the table name as a command argument" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdFields.run(@options ++ ~w[--apps-table custom_apps --grants-table custom_grants])
        content = get_migration_content!()

        assert content =~
                 """
                     alter table(:custom_apps) do
                       add :open_id_post_logout_redirect_uri, :string
                 """

        assert content =~
                 """
                     alter table(:custom_grants) do
                       add :open_id_nonce, :string
                 """

        assert content =~ "unique_index(:custom_grants, [:open_id_nonce])"
      end)
    end
  end

  test "doesn't create the file when the migration already exists" do
    File.cd!(@tmp_path, fn ->
      AddOpenIdFields.run(@options)

      assert_raise Mix.Error,
                   "migration can't be created, there is already a migration file with name AddOpenIdFields.",
                   fn ->
                     AddOpenIdFields.run(@options)
                   end
    end)
  end
end
