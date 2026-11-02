defmodule NoraSmoke do
  def run do
    %{"message" => "elixir through nora"} = Jason.decode!(~s({"message":"elixir through nora"}))
    IO.puts("elixir through nora")
  end
end
