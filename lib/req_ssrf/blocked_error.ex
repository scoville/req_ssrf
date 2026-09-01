defmodule ReqSSRF.BlockedError do
  @moduledoc """
  Exception that is raised if a URL fails the SSRF check.

  See `ReqSSRF`.
  """

  defexception [:url, :reason]

  @type t :: %__MODULE__{
          url: String.t() | URI.t(),
          reason: ReqSSRF.reason()
        }

  @impl Exception
  def message(%__MODULE__{url: url, reason: reason}) do
    "refused to fetch #{to_string(url)}: #{describe(reason)}"
  end

  defp describe(:invalid_url), do: "the URL cannot be parsed"
  defp describe(:missing_host), do: "the URL has no host"
  defp describe(:unsupported_scheme), do: "the scheme is not allowed"
  defp describe(:ip_address), do: "the host is an IP address"
  defp describe(:unresolvable_host), do: "the host does not resolve"
  defp describe(:reserved_address), do: "the host is not on the internet"
end
