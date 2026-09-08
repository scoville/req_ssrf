# mix run bench/check.exs

resolver_v4 = fn
  _host, :inet, _timeout -> {:ok, [{93, 184, 216, 34}]}
  _host, :inet6, _timeout -> {:ok, []}
end

resolver_dual = fn
  _host, :inet, _timeout ->
    {:ok, [{93, 184, 216, 34}, {93, 184, 216, 35}]}

  _host, :inet6, _timeout ->
    {:ok, [{0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946}]}
end

deny = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]

Benchee.run(
  %{
    "ip address, allowed" => fn ->
      ReqSSRF.check("http://93.184.216.34/some/path?q=1")
    end,
    "ip address, reserved" => fn ->
      ReqSSRF.check("http://169.254.169.254/latest/meta-data/")
    end,
    "ipv6 address, allowed" => fn ->
      ReqSSRF.check("http://[2606:2800:220:1:248:1893:25c8:1946]/")
    end,
    "ipv4-mapped ipv6, reserved" => fn ->
      ReqSSRF.check("http://[::ffff:169.254.169.254]/")
    end,
    "unsupported scheme" => fn ->
      ReqSSRF.check("file:///etc/passwd")
    end,
    "hostname, single address" => fn ->
      ReqSSRF.check("http://example.com/", resolver: resolver_v4)
    end,
    "hostname, dual stack" => fn ->
      ReqSSRF.check("http://example.com/", resolver: resolver_dual)
    end,
    "ip address, three deny ranges" => fn ->
      ReqSSRF.check("http://93.184.216.34/", deny: deny)
    end,
    "uri struct, allowed" => fn ->
      ReqSSRF.check(URI.parse("http://93.184.216.34/some/path?q=1"))
    end
  },
  warmup: 1,
  time: 3,
  memory_time: 1,
  reduction_time: 1
)
