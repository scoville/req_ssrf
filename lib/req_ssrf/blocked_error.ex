defmodule ReqSSRF.BlockedError do
  @moduledoc """
  Exception that is raised if a URL fails the SSRF check.

  The userinfo of the URL is redacted in the exception message and when the
  struct is inspected, since a submitted URL can contain credentials and the
  struct ends up in log lines.

  See `ReqSSRF`.
  """

  defexception [:url, :reason]

  @type t :: %__MODULE__{
          url: String.t() | URI.t(),
          reason: ReqSSRF.reason()
        }

  @impl Exception
  def message(%__MODULE__{url: url, reason: reason}) do
    "refused to fetch #{redact(url)}: #{describe(reason)}"
  end

  @doc false
  def redact(%URI{userinfo: nil} = uri), do: uri
  def redact(%URI{} = uri), do: %{uri | userinfo: "***"}

  def redact(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, uri} -> URI.to_string(redact(uri))
      {:error, _} -> url
    end
  end

  def redact(url), do: url

  defp describe(:invalid_url), do: "the URL cannot be parsed"
  defp describe(:missing_host), do: "the URL has no host"
  defp describe(:unsupported_scheme), do: "the scheme is not allowed"
  defp describe(:ip_address), do: "the host is an IP address"
  defp describe(:unresolvable_host), do: "the host does not resolve"
  defp describe(:resolution_failed), do: "the host could not be resolved"
  defp describe(:reserved_address), do: "the host is not on the internet"
  defp describe(:denied_address), do: "the host is in a denied range"

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%{url: url, reason: reason}, opts) do
      container_doc(
        "%ReqSSRF.BlockedError{",
        [url: @for.redact(url), reason: reason],
        "}",
        opts,
        fn {key, value}, opts ->
          concat([Atom.to_string(key), ": ", to_doc(value, opts)])
        end
      )
    end
  end
end
