defmodule ReqSSRF do
  @moduledoc """
  Decides whether the server may fetch a URL that somebody else chose.

  A server that fetches a user-given URL can be pointed at the internal network,
  e.g. at another internal service, a database admin page, or the cloud
  provider's metadata endpoint. This module validates a URL against a list of
  reserved URLs. `attach/2` ensures that every redirect hop of a `Req` request
  is validated.

  The documentation of `public_address?/1` lists the reserved ranges.
  See [README](readme.html) for more details on what the library does and does
  not do.
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

  defguardp is_ipv4(a, b, c, d)
            when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255

  defguardp is_ipv6(a, b, c, d, e, f, g, h)
            when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and
                   d in 0..0xFFFF and e in 0..0xFFFF and f in 0..0xFFFF and
                   g in 0..0xFFFF and h in 0..0xFFFF

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
  URL when following redirects. If you use a different HTTP client that follows
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
      opts
      |> Keyword.validate!(allow_ip_address: true, schemes: @default_schemes)
      |> validate_values!()

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

  ## Reserved ranges

  An IPv4 address is refused if it falls in one of the IANA special-purpose
  ranges. `168.63.129.16/32` among them is Azure's host endpoint.

  #{Enum.map_join(@ipv4_ranges, "\n", &"- `#{&1}`")}

  For IPv6, `#{@global_unicast}` is the only range IANA has allocated for
  global unicast, so an address outside it is refused without enumerating
  anything. These special-purpose ranges inside it are refused as well.

  #{Enum.map_join(@ipv6_ranges, "\n", &"- `#{&1}`")}

  ## Examples

      iex> public_address?({8, 8, 8, 8})
      true

      iex> public_address?({169, 254, 169, 254})
      false

      iex> public_address?({0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE})
      false
  """
  @spec public_address?(:inet.ip_address()) :: boolean
  def public_address?({a, b, c, d} = address) when is_ipv4(a, b, c, d) do
    not reserved?(address)
  end

  def public_address?({a, b, c, d, e, f, g, h} = address)
      when is_ipv6(a, b, c, d, e, f, g, h) do
    not reserved?(unmap(address))
  end

  defp validate_values!(opts) do
    Keyword.new(opts, fn {key, value} -> {key, validate_value!(key, value)} end)
  end

  defp validate_value!(:allow_ip_address, value) do
    if is_boolean(value) do
      value
    else
      raise ArgumentError, """
      invalid :allow_ip_address option

      Expected a boolean.

          value: #{inspect(value)}
      """
    end
  end

  # A scheme is case insensitive and `URI` downcases the one it parses, so the
  # given list is downcased to match rather than refusing every URL.
  defp validate_value!(:schemes, value) do
    if is_list(value) and value != [] and Enum.all?(value, &is_binary/1) do
      Enum.map(value, &String.downcase/1)
    else
      raise ArgumentError, """
      invalid :schemes option

      Expected a non-empty list of strings, e.g. ["http", "https"].

          value: #{inspect(value)}
      """
    end
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
      {:ok, _address} when allow_ip_address == false -> {:error, :ip_address}
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

  Takes the same options as `check/2`.

  The `:ssrf_check` request option decides what a single request does:

  - `true` - run the check with the options given to `attach/2`. This is the
    default.
  - `false` - skip the check for this request.
  - a keyword list - run the check with these options on top of the ones given
    to `attach/2`, so an option that is not named keeps its attached value.

  Any other value raises `ArgumentError`, since a value that is neither of the
  above would otherwise skip the check silently.

  ## Examples

      Req.new()
      |> ReqSSRF.attach(allow_ip_address: false)
      |> Req.get(url: submitted_url)

  Skipping the check for one request:

      Req.get(request, url: internal_url, ssrf_check: false)

  Allowing an IP address for one request, keeping every other attached option:

      Req.get(request, url: url, ssrf_check: [allow_ip_address: true])
  """
  @spec attach(Req.Request.t(), opts()) :: Req.Request.t()
  def attach(%Req.Request{} = request, opts \\ []) do
    opts =
      opts
      |> Keyword.validate!([:allow_ip_address, :schemes])
      |> validate_values!()

    request
    |> Req.Request.register_options([:ssrf_check])
    |> Req.merge(ssrf_check: true)
    |> Req.Request.append_request_steps(ssrf_check: &check_url(&1, opts))
  end

  defp check_url(%Req.Request{options: %{ssrf_check: false}} = request, _opts) do
    request
  end

  defp check_url(%Req.Request{options: %{ssrf_check: true}} = request, opts) do
    run_check(request, opts)
  end

  defp check_url(
         %Req.Request{options: %{ssrf_check: overrides}} = request,
         opts
       )
       when is_list(overrides) do
    run_check(request, Keyword.merge(opts, overrides))
  end

  defp check_url(%Req.Request{options: options}, _opts) do
    raise ArgumentError, """
    invalid :ssrf_check option

    Expected true to run the check, false to skip it, or a keyword list of
    options to override the ones given to ReqSSRF.attach/2.

        value: #{inspect(Map.get(options, :ssrf_check))}
    """
  end

  defp run_check(request, opts) do
    case check(request.url, opts) do
      :ok ->
        request

      {:error, reason} ->
        error = %BlockedError{url: request.url, reason: reason}
        Req.Request.halt(request, error)
    end
  end
end
