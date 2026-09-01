defmodule ReqSSRF.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/scoville/req_ssrf"

  def project do
    [
      app: :req_ssrf,
      version: @version,
      name: "ReqSSRF",
      source_url: @source_url,
      homepage_url: @source_url,
      description: description(),
      package: package(),
      docs: docs(),
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      dialyzer: [
        flags: [
          :error_handling,
          :extra_return,
          :missing_return,
          :underspecs,
          :unmatched_returns,
          :unknown
        ],
        # Configure ignore file. The file uses the short format:
        # mix dialyzer --format ignore_file_strict
        ignore_warnings: ".dialyzer_ignore.exs",
        # Fail if the ignore files has unused filters (e.g. after a
        # dependency fixed an issue)
        list_unused_filters: true,
        # Set location of the persistent lookup table
        plt_local_path: ".plts"
      ]
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        "coveralls.json": :test,
        "coveralls.github": :test
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    "Req plugin that prevents Server Side Request Forgery"
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "== 1.7.19", only: [:dev, :test], runtime: false},
      {:dialyxir, "== 1.4.7", only: [:dev], runtime: false},
      {:ex_doc, "== 0.40.3", only: :dev, runtime: false},
      {:excoveralls, "== 0.18.5", only: :test},
      {:inet_cidr, "~> 1.0"},
      {:makeup_diff, "== 0.1.1", only: :dev, runtime: false},
      {:plug, "~> 1.0", only: :test},
      {:req, "~> 0.7"}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => @source_url <> "/blob/main/CHANGELOG.md"
      },
      files: ~w(lib mix.exs LICENSE README* CHANGELOG*)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: @version,
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"]
    ]
  end
end
