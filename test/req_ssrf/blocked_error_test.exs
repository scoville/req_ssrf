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
  end
end
