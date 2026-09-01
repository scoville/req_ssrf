defmodule ReqSSRF.BlockedErrorTest do
  use ExUnit.Case, async: true

  alias ReqSSRF.BlockedError

  describe "message/1" do
    test "names the URL and the reason" do
      reasons = [
        invalid_url: "cannot be parsed",
        missing_host: "no host",
        unsupported_scheme: "scheme is not allowed",
        ip_address: "an IP address",
        unresolvable_host: "does not resolve",
        resolution_failed: "could not be resolved",
        reserved_address: "not on the internet"
      ]

      for {reason, description} <- reasons do
        error = %BlockedError{url: "http://8.8.8.8/", reason: reason}
        message = Exception.message(error)

        assert message =~ "http://8.8.8.8/"
        assert message =~ description
      end
    end

    test "accepts a URI struct" do
      error = %BlockedError{
        url: URI.new!("http://8.8.8.8/"),
        reason: :reserved_address
      }

      assert Exception.message(error) =~ "http://8.8.8.8/"
    end

    test "redacts the userinfo" do
      for url <- [
            "https://alice:s3cret@127.0.0.1/x",
            URI.new!("https://alice:s3cret@127.0.0.1/x")
          ] do
        message =
          Exception.message(%BlockedError{url: url, reason: :ip_address})

        assert message =~ "https://***@127.0.0.1/x"
        refute message =~ "alice"
        refute message =~ "s3cret"
      end
    end

    test "leaves a URL without userinfo alone" do
      error = %BlockedError{url: "http://127.0.0.1/x", reason: :ip_address}
      assert Exception.message(error) =~ "http://127.0.0.1/x"
    end

    test "keeps a URL it cannot parse" do
      error = %BlockedError{url: "http://[oops]/", reason: :invalid_url}
      assert Exception.message(error) =~ "http://[oops]/"
    end

    test "does not raise without a URL" do
      error = %BlockedError{reason: :missing_host}

      assert Exception.message(error) ==
               "refused to fetch : the URL has no host"
    end
  end

  describe "inspect/1" do
    test "redacts the userinfo and keeps the reason" do
      error = %BlockedError{
        url: "https://alice:s3cret@127.0.0.1/x",
        reason: :reserved_address
      }

      inspected = inspect(error)

      assert inspected =~ "https://***@127.0.0.1/x"
      assert inspected =~ "reason: :reserved_address"
      refute inspected =~ "alice"
      refute inspected =~ "s3cret"
    end

    test "shows a URL without userinfo unchanged" do
      error = %BlockedError{url: "http://127.0.0.1/", reason: :ip_address}
      assert inspect(error) =~ ~s(url: "http://127.0.0.1/")
    end

    test "redacts the userinfo of a URI struct" do
      error = %BlockedError{
        url: URI.new!("https://alice:s3cret@127.0.0.1/x"),
        reason: :reserved_address
      }

      inspected = inspect(error)

      assert inspected =~ ~s(userinfo: "***")
      refute inspected =~ "alice"
      refute inspected =~ "s3cret"
    end

    test "returns valid Elixir that evaluates back to the redacted error" do
      for url <- [
            "https://alice:s3cret@127.0.0.1/x",
            URI.new!("https://alice:s3cret@127.0.0.1/x"),
            "http://127.0.0.1/",
            nil
          ] do
        error = %BlockedError{url: url, reason: :reserved_address}

        assert {evaluated, _} = Code.eval_string(inspect(error))

        assert evaluated == %BlockedError{
                 url: BlockedError.redact(url),
                 reason: :reserved_address
               }
      end
    end
  end
end
