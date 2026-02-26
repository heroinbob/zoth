require Mix.Zoth.Migration

binary_id = if System.get_env("UUID"), do: true, else: false

"CreateOauthTables"
|> Mix.Zoth.Migration.gen("oauth", %{
  repo: Zoth.Test.Repo,
  binary_id: binary_id,
  device_code: true
})
|> Code.eval_string()
