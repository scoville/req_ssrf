defmodule ReqSSRFTest do
  use ExUnit.Case, async: true

  alias ReqSSRF
  alias ReqSSRF.BlockedError

  doctest ReqSSRF, import: true

  describe "check/2" do
    test "allows an address the internet can route to" do
      assert ReqSSRF.check("http://8.8.8.8/") == :ok
      assert ReqSSRF.check("https://8.8.8.8/path?query=1") == :ok
      assert ReqSSRF.check("http://[2606:4700:4700::1111]/") == :ok
      assert ReqSSRF.check("http://[::ffff:8.8.8.8]/") == :ok
    end

    test "accepts a URI struct" do
      assert ReqSSRF.check(URI.new!("http://8.8.8.8/")) == :ok

      assert ReqSSRF.check(URI.new!("http://127.0.0.1/")) ==
               {:error, :reserved_address}
    end

    test "rejects a reserved address" do
      for url <- [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[2002:a9fe:a9fe::]/"
          ] do
        assert ReqSSRF.check(url) == {:error, :reserved_address}
      end
    end

    test "reads every notation of an address the same way" do
      for url <- [
            "http://0x7f.1/",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://127.1/"
          ] do
        assert ReqSSRF.check(url) == {:error, :reserved_address}
      end
    end

    test "resolves a host name" do
      assert ReqSSRF.check("http://localhost/") == {:error, :reserved_address}
    end

    test "checks the host and not the userinfo" do
      assert ReqSSRF.check("http://8.8.8.8@127.0.0.1/") ==
               {:error, :reserved_address}

      assert ReqSSRF.check("http://127.0.0.1@8.8.8.8/") == :ok
    end

    test "rejects any address when allow_ip_address is false" do
      opts = [allow_ip_address: false]

      assert ReqSSRF.check("http://8.8.8.8/", opts) == {:error, :ip_address}

      assert ReqSSRF.check("http://[2606:4700:4700::1111]/", opts) ==
               {:error, :ip_address}

      assert ReqSSRF.check("http://2130706433/", opts) == {:error, :ip_address}
      assert ReqSSRF.check("http://127.0.0.1/", opts) == {:error, :ip_address}
    end

    test "reads every notation as an address when allow_ip_address is false" do
      opts = [allow_ip_address: false]

      for host <- [
            "0x7f.1",
            "0x7f000001",
            "0X7F000001",
            "0177.0.0.1",
            "127.1",
            "127.0.1",
            "127.0.0.01",
            "0",
            "[::1]",
            "[::ffff:127.0.0.1]"
          ] do
        assert ReqSSRF.check("http://#{host}/", opts) == {:error, :ip_address}
      end
    end

    test "refuses an address written with a trailing dot" do
      assert ReqSSRF.check("http://8.8.8.8./", allow_ip_address: false) in [
               {:error, :ip_address},
               {:error, :unresolvable_host}
             ]

      assert ReqSSRF.check("http://127.0.0.1./") in [
               {:error, :reserved_address},
               {:error, :unresolvable_host}
             ]
    end

    test "rejects a scheme that is not allowed" do
      assert ReqSSRF.check("file:///etc/passwd") ==
               {:error, :unsupported_scheme}

      assert ReqSSRF.check("gopher://8.8.8.8/") ==
               {:error, :unsupported_scheme}

      assert ReqSSRF.check("http://8.8.8.8/", schemes: ["https"]) ==
               {:error, :unsupported_scheme}
    end

    test "rejects a URL without a host" do
      assert ReqSSRF.check("http://") == {:error, :missing_host}
      assert ReqSSRF.check("/relative/path") == {:error, :unsupported_scheme}
      assert ReqSSRF.check("") == {:error, :unsupported_scheme}
    end

    test "rejects a host that does not resolve" do
      assert ReqSSRF.check("http://nonexistent.invalid/") ==
               {:error, :unresolvable_host}
    end

    test "rejects a URL that cannot be parsed" do
      assert ReqSSRF.check("http://[oops]/") == {:error, :invalid_url}
    end

    test "raises on an unknown option" do
      assert_raise ArgumentError, fn ->
        ReqSSRF.check("http://8.8.8.8/", allow_ip_addresses: false)
      end
    end

    test "raises on an allow_ip_address that is not a boolean" do
      for value <- [nil, "yes", 1, :yes] do
        assert_raise ArgumentError,
                     ~r/invalid :allow_ip_address option/,
                     fn ->
                       ReqSSRF.check("http://8.8.8.8/",
                         allow_ip_address: value
                       )
                     end
      end
    end

    test "reads a scheme regardless of case" do
      assert ReqSSRF.check("http://8.8.8.8/", schemes: ["HTTP"]) == :ok
      assert ReqSSRF.check("HTTP://8.8.8.8/", schemes: ["http"]) == :ok

      assert ReqSSRF.check("http://8.8.8.8/", schemes: ["HTTPS"]) ==
               {:error, :unsupported_scheme}
    end

    test "raises on schemes that are not a non-empty list of strings" do
      for value <- ["https", [:http], [], ["http", :https], nil] do
        assert_raise ArgumentError, ~r/invalid :schemes option/, fn ->
          ReqSSRF.check("http://8.8.8.8/", schemes: value)
        end
      end
    end
  end

  describe "allowed?/2" do
    test "returns the answer without the reason" do
      assert ReqSSRF.allowed?("http://8.8.8.8/")
      refute ReqSSRF.allowed?("http://127.0.0.1/")
    end
  end

  describe "public_address?/1" do
    test "accepts a global unicast address" do
      assert ReqSSRF.public_address?({8, 8, 8, 8})
      assert ReqSSRF.public_address?({203, 0, 114, 1})
      assert ReqSSRF.public_address?({192, 0, 1, 1})
      assert ReqSSRF.public_address?({168, 63, 129, 15})
      assert ReqSSRF.public_address?({168, 63, 129, 17})

      assert ReqSSRF.public_address?(
               {0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111}
             )

      assert ReqSSRF.public_address?({0x2000, 0, 0, 0, 0, 0, 0, 1})
      assert ReqSSRF.public_address?({0x3FFE, 0, 0, 0, 0, 0, 0, 1})
      assert ReqSSRF.public_address?({0x2001, 0x200, 0, 0, 0, 0, 0, 1})
    end

    test "rejects a reserved IPv4 address" do
      assert Enum.all?(
               [
                 {0, 0, 0, 0},
                 {10, 1, 2, 3},
                 {100, 64, 0, 1},
                 {100, 100, 100, 200},
                 {127, 0, 0, 1},
                 {168, 63, 129, 16},
                 {169, 254, 169, 254},
                 {172, 16, 0, 1},
                 {172, 31, 255, 254},
                 {192, 0, 0, 1},
                 {192, 0, 0, 192},
                 {192, 0, 2, 1},
                 {192, 88, 99, 1},
                 {192, 168, 1, 1},
                 {198, 18, 0, 1},
                 {198, 51, 100, 1},
                 {203, 0, 113, 1},
                 {224, 0, 0, 1},
                 {255, 255, 255, 255}
               ],
               &(not ReqSSRF.public_address?(&1))
             )
    end

    test "rejects an IPv6 address outside global unicast" do
      # ::, ::1, 100::1, 5f00::1, fd00::1, fe80::1, ff02::1, 1fff::1, 4000::1
      refute ReqSSRF.public_address?({0, 0, 0, 0, 0, 0, 0, 0})
      refute ReqSSRF.public_address?({0, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x100, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x5F00, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0xFD00, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0xFE80, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0xFF02, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x1FFF, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x4000, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x64, 0xFF9B, 0, 0, 0, 0, 0xA9FE, 0xA9FE})
    end

    test "rejects a special-purpose range inside global unicast" do
      # 2001::1, 2001:db8::1, 2002:a9fe:a9fe::, 3fff::1
      refute ReqSSRF.public_address?({0x2001, 0, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1})
      refute ReqSSRF.public_address?({0x2002, 0xA9FE, 0xA9FE, 0, 0, 0, 0, 0})
      refute ReqSSRF.public_address?({0x3FFF, 0, 0, 0, 0, 0, 0, 1})
    end

    test "raises on a tuple that is not an IP address" do
      for value <- [
            {999, 0, 0, 1},
            {-1, 0, 0, 1},
            {0, 0, 0, 0, 0, 0, 0, 0x10000},
            {1, 2, 3},
            "8.8.8.8"
          ] do
        assert_raise FunctionClauseError, fn ->
          ReqSSRF.public_address?(value)
        end
      end
    end

    test "matches an IPv4-mapped address against the IPv4 ranges" do
      # ::ffff:169.254.169.254 and ::ffff:8.8.8.8
      refute ReqSSRF.public_address?({0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE})
      assert ReqSSRF.public_address?({0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808})
    end
  end

  describe "attach/2" do
    test "makes a request to an allowed URL" do
      Req.Test.stub(__MODULE__, fn conn ->
        Req.Test.text(conn, "hello")
      end)

      assert {:ok, %Req.Response{status: 200, body: "hello"}} =
               request("http://8.8.8.8/")
    end

    test "halts a request to a reserved address" do
      Req.Test.stub(__MODULE__, fn conn ->
        Req.Test.text(conn, "hello")
      end)

      assert {:error, %BlockedError{reason: :reserved_address} = error} =
               request("http://169.254.169.254/latest/meta-data/")

      assert Exception.message(error) =~ "not on the internet"
    end

    test "checks the URL that the base URL and path resolve to" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}, base_url: "http://127.0.0.1"]
        |> Req.new()
        |> ReqSSRF.attach()

      assert {:error, %BlockedError{reason: :reserved_address}} =
               Req.get(request, url: "/some/path")
    end

    test "checks every hop of a redirect chain" do
      Req.Test.stub(__MODULE__, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/")
        |> Plug.Conn.send_resp(302, "")
      end)

      assert {:error, %BlockedError{reason: :reserved_address} = error} =
               request("http://8.8.8.8/")

      assert error.url.host == "169.254.169.254"
    end

    test "does not see a URL that a later request step sets" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      rewrite = fn request ->
        %{request | url: URI.parse("http://127.0.0.1/")}
      end

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()
        |> Req.Request.append_request_steps(rewrite: rewrite)

      assert {:ok, %Req.Response{status: 200}} =
               Req.get(request, url: "http://8.8.8.8/")
    end

    test "skips the check when ssrf_check is false" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()

      assert {:ok, %Req.Response{status: 200}} =
               Req.get(request, url: "http://127.0.0.1/", ssrf_check: false)
    end

    test "runs the check with the attached options when ssrf_check is true" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach(allow_ip_address: false)

      assert {:error, %BlockedError{reason: :ip_address}} =
               Req.get(request, url: "http://8.8.8.8/", ssrf_check: true)
    end

    test "keeps the attached options a request does not override" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach(allow_ip_address: false)

      assert {:error, %BlockedError{reason: :ip_address}} =
               Req.get(request,
                 url: "http://8.8.8.8/",
                 ssrf_check: [schemes: ["http"]]
               )

      assert {:error, %BlockedError{reason: :unsupported_scheme}} =
               Req.get(request,
                 url: "http://8.8.8.8/",
                 ssrf_check: [schemes: ["https"], allow_ip_address: true]
               )
    end

    test "overrides an attached option for a single request" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach(allow_ip_address: false)

      assert {:ok, %Req.Response{status: 200}} =
               Req.get(request,
                 url: "http://8.8.8.8/",
                 ssrf_check: [allow_ip_address: true]
               )
    end

    test "raises on an ssrf_check value that is neither a boolean nor options" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()

      for value <- [nil, %{}, :yes, 1, "false"] do
        assert_raise ArgumentError, ~r/invalid :ssrf_check option/, fn ->
          Req.get(request, url: "http://127.0.0.1/", ssrf_check: value)
        end
      end
    end

    test "raises when the ssrf_check option was removed" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()
        |> Req.Request.delete_option(:ssrf_check)

      assert_raise ArgumentError, ~r/invalid :ssrf_check option/, fn ->
        Req.get(request, url: "http://127.0.0.1/")
      end
    end

    test "checks the request when ssrf_check is an empty list" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()

      assert {:error, %BlockedError{reason: :reserved_address}} =
               Req.get(request, url: "http://127.0.0.1/", ssrf_check: [])
    end

    test "passes its options to the check" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach(allow_ip_address: false)

      assert {:error, %BlockedError{reason: :ip_address}} =
               Req.get(request, url: "http://8.8.8.8/")
    end

    test "raises on an unknown option" do
      assert_raise ArgumentError, fn ->
        ReqSSRF.attach(Req.new(), allow_ip_addresses: false)
      end
    end

    test "raises on an invalid option value when attaching" do
      assert_raise ArgumentError, ~r/invalid :schemes option/, fn ->
        ReqSSRF.attach(Req.new(), schemes: "https")
      end

      assert_raise ArgumentError, ~r/invalid :allow_ip_address option/, fn ->
        ReqSSRF.attach(Req.new(), allow_ip_address: nil)
      end
    end

    test "raises on an invalid option value overridden on a request" do
      Req.Test.stub(__MODULE__, fn conn -> Req.Test.text(conn, "hello") end)

      request =
        [plug: {Req.Test, __MODULE__}]
        |> Req.new()
        |> ReqSSRF.attach()

      assert_raise ArgumentError, ~r/invalid :allow_ip_address option/, fn ->
        Req.get(request,
          url: "http://8.8.8.8/",
          ssrf_check: [allow_ip_address: nil]
        )
      end
    end
  end

  defp request(url) do
    [plug: {Req.Test, __MODULE__}]
    |> Req.new()
    |> ReqSSRF.attach()
    |> Req.get(url: url)
  end
end
