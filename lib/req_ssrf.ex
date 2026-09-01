defmodule ReqSSRF do
  @moduledoc """
  Decides whether the server may fetch a URL that somebody else chose.

  A server that fetches a user-given URL can be pointed at the internal network,
  e.g. at another internal service, a database admin page, or the cloud
  provider's metadata endpoint. This module validates a URL against a list of
  reserved URLs. `attach/2` ensures that every redirect hop of a `Req` request
  is validated.

  A host written as an IP address is matched against the reserved ranges in
  whatever notation it is written: `:inet.parse_address/1` reads `127.0.0.1`,
  `2130706433` and `[::ffff:10.0.0.1]` alike. A caller with no use for literal
  hosts can refuse them with `allow_ip_address: false`.

  A name is resolved with `:inet.getaddrs/2`, the resolver `Finch` uses, so
  the check and the request that follows ask the same resolver. Every address
  in the answer has to be one the internet can route to. A host that does not
  resolve is refused.

  ## Use the step, not the predicate

  `allowed?/2` and `check/2` check a single URL. That is not enough on its own,
  because `Req` follows redirects by default. If only the given URL is checked,
  a host that passes that check can respond with
  `302 Location: http://169.254.169.254/` to point the server at an internal
  endpoint.

  `attach/2` adds the check as a request step to a `Req` request. `Req` re-runs
  the request steps for each redirect, which means that every hop is checked by
  this module.

  Only use `check/2` directly when you are not making the request, for example
  if you are validating a URL the user is saving.

  ## Residual risk: DNS rebinding

  The addresses are checked, and then the host is resolved again when the
  connection is made. A resolver under the attacker's control can answer
  differently the second time, so a name that passed can still connect to a
  reserved address. This needs a nameserver the attacker controls, while the
  redirect that `attach/2` closes needs only one response header.

  The library does not close it. Closing it in the application means
  connecting to the validated address while keeping the `Host` header, the TLS
  server name and the certificate hostname check, and getting any of the three
  wrong turns certificate verification off without saying so.

  Using this module therefore means accepting that a host whose DNS the
  attacker controls can reach any address the server routes to. Deny egress to
  the private ranges and the metadata endpoint at the network if that is not
  acceptable. That also covers the fetches nobody remembered to check, which
  this module cannot.

  ## What else the check leaves open

  Nothing connects to a refused URL, so a user cannot find out what is listening
  on an internal address. Two things remain.

  The first is the reason for a refusal. `ReqSSRF.BlockedError` says
  whether the name failed to resolve or resolved to a reserved address, which
  tells a user which names your resolver knows and a public one does not: inside
  a VPC, submitting `db.internal` reveals whether it exists. Do not show the
  reason to whoever supplied the URL.

  The second is the fetch itself. A user learns little from a URL that passes,
  since they can reach a public host without your help, but the request goes out
  from your server's address rather than theirs. Yours is the address in the
  target's logs and the one blocked for abuse, and a service that allowlists
  your IP range will take a request from your server that it would refuse from
  the user. Rate limit the paths that fetch on a user's behalf.
  """

  alias ReqSSRF.BlockedError

  @default_schemes ~w[http https]

  # IANA special-purpose IPv4 ranges
  @ipv4_ranges [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    # Azure's host endpoint
    "168.63.129.16/32",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4"
  ]

  # IPv6 is the other way round: `2000::/3` is the only range IANA has
  # allocated for global unicast, so an address outside it is refused without
  # enumeration. That leaves the special-purpose ranges inside it:
  # documentation, IETF protocol assignments, and 6to4, which embeds an IPv4
  # address.
  @global_unicast "2000::/3"

  @ipv6_ranges [
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20"
  ]

  @parsed_global_unicast InetCidr.parse_cidr!(@global_unicast)
  @parsed_ipv4_ranges Enum.map(@ipv4_ranges, &InetCidr.parse_cidr!/1)
  @parsed_ipv6_ranges Enum.map(@ipv6_ranges, &InetCidr.parse_cidr!/1)

  @typedoc """
  The reason why a URL may not be fetched.
  """
  @type reason ::
          :invalid_url
          | :missing_host
          | :unsupported_scheme
          | :ip_address
          | :unresolvable_host
          | :reserved_address

  @typedoc """
  Options for `check/2` and `allowed?/2`.

  - `:allow_ip_address` - whether a host written as an IP address is accepted.
    Defaults to `true`.
  - `:schemes` - the accepted URL schemes. Defaults to
    `#{inspect(@default_schemes)}`.
  """
  @type opts :: [allow_ip_address: boolean, schemes: [String.t()]]

  @doc """
  Returns `:ok` if the URL may be fetched, or `{:error, reason}` if it may not.

  If you use `Req`, use `attach/2` instead. This ensures that Req checks every
  URL when following redirects. If you use a different HTTP client that follows,
  redirects, you must check every URL that is redirected to yourself.

  ## Examples

      iex> check("http://8.8.8.8/")
      :ok

      iex> check("http://169.254.169.254/latest/meta-data/")
      {:error, :reserved_address}

      iex> check("file:///etc/passwd")
      {:error, :unsupported_scheme}

      iex> check("http://8.8.8.8/", allow_ip_address: false)
      {:error, :ip_address}
  """
  @spec check(String.t() | URI.t(), opts()) :: :ok | {:error, reason()}
  def check(url, opts \\ [])

  def check(url, opts) when is_binary(url) do
    case URI.new(url) do
      {:ok, uri} -> check(uri, opts)
      {:error, _} -> {:error, :invalid_url}
    end
  end

  def check(%URI{} = uri, opts) do
    opts =
      Keyword.validate!(opts,
        allow_ip_address: true,
        schemes: @default_schemes
      )

    with :ok <- check_scheme(uri, Keyword.fetch!(opts, :schemes)),
         {:ok, addresses} <-
           resolve(uri.host, Keyword.fetch!(opts, :allow_ip_address)) do
      if Enum.all?(addresses, &public_address?/1) do
        :ok
      else
        {:error, :reserved_address}
      end
    end
  end

  @doc """
  Returns `true` if the URL may be fetched and `false` otherwise.

  Same as `check/2`, but returns a boolean.

  ## Examples

      iex> allowed?("http://8.8.8.8/")
      true

      iex> allowed?("http://127.0.0.1/")
      false
  """
  @spec allowed?(String.t() | URI.t(), opts()) :: boolean
  def allowed?(url, opts \\ []), do: check(url, opts) == :ok

  @doc """
  Returns `true` if the given IP address is one the internet can route to and
  `false` otherwise.

  An IPv4-mapped IPv6 address points to the same host as its IPv4 form and is
  matched against the IPv4 ranges.

  ## Examples

      iex> public_address?({8, 8, 8, 8})
      true

      iex> public_address?({169, 254, 169, 254})
      false

      iex> public_address?({0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE})
      false
  """
  @spec public_address?(:inet.ip_address()) :: boolean
  def public_address?(address) when tuple_size(address) in [4, 8] do
    not reserved?(unmap(address))
  end

  defp check_scheme(%URI{scheme: scheme}, schemes) do
    if scheme in schemes do
      :ok
    else
      {:error, :unsupported_scheme}
    end
  end

  defp reserved?({_, _, _, _} = address) do
    Enum.any?(@parsed_ipv4_ranges, &InetCidr.contains?(&1, address))
  end

  defp reserved?(address) do
    not InetCidr.contains?(@parsed_global_unicast, address) or
      Enum.any?(@parsed_ipv6_ranges, &InetCidr.contains?(&1, address))
  end

  defp unmap({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    {div(ab, 256), rem(ab, 256), div(cd, 256), rem(cd, 256)}
  end

  defp unmap(address), do: address

  defp resolve(host, _allow_ip_address) when host in [nil, ""] do
    {:error, :missing_host}
  end

  defp resolve(host, allow_ip_address) do
    charlist = to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, _address} when not allow_ip_address -> {:error, :ip_address}
      {:ok, address} -> {:ok, [address]}
      {:error, :einval} -> resolve_name(charlist)
    end
  end

  defp resolve_name(hostname) do
    case getaddrs(hostname, :inet) ++ getaddrs(hostname, :inet6) do
      [] -> {:error, :unresolvable_host}
      addresses -> {:ok, Enum.uniq(addresses)}
    end
  end

  defp getaddrs(host, family) do
    case :inet.getaddrs(host, family) do
      {:ok, addresses} -> addresses
      {:error, _reason} -> []
    end
  end

  ## Req integration

  @doc """
  Checks the URL of every hop of a `Req` request.

  The check runs as a request step appended after the steps that build the
  URL, so it sees the URL that is about to be requested, and `Req` re-runs it
  for each redirect.

  A request whose URL may not be fetched is halted with
  `ReqSSRF.BlockedError`. `Req.request/2` returns
  `{:error, %ReqSSRF.BlockedError{}}` and `Req.request!/2` raises it.

  Takes the same options as `check/2`. They are stored under the single
  `:ssrf_check` request option. Pass `ssrf_check: false` on a request to skip the
  check.

  ## Examples

      Req.new()
      |> ReqSSRF.attach(allow_ip_address: false)
      |> Req.get(url: submitted_url)
  """
  @spec attach(Req.Request.t(), opts()) :: Req.Request.t()
  def attach(%Req.Request{} = request, opts \\ []) do
    opts = Keyword.validate!(opts, [:allow_ip_address, :schemes])

    request
    |> Req.Request.register_options([:ssrf_check])
    |> Req.merge(ssrf_check: opts)
    |> Req.Request.append_request_steps(ssrf_check: &check_url/1)
  end

  defp check_url(%Req.Request{options: %{ssrf_check: opts}} = request)
       when is_list(opts) do
    case check(request.url, opts) do
      :ok ->
        request

      {:error, reason} ->
        error = %BlockedError{url: request.url, reason: reason}
        Req.Request.halt(request, error)
    end
  end

  defp check_url(%Req.Request{} = request), do: request
end
