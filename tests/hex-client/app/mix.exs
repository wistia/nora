defmodule NoraSmoke.MixProject do
  use Mix.Project
  def project, do: [app: :nora_smoke, version: "0.1.0", elixir: "~> 1.20", deps: [{:jason, "1.4.4"}]]
  def application, do: [extra_applications: [:logger]]
end
