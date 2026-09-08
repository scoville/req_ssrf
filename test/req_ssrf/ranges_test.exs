defmodule ReqSSRF.RangesTest do
  use ExUnit.Case, async: true

  alias ReqSSRF.Ranges

  defmodule Clauses do
    alias ReqSSRF.Ranges

    @cidrs ~w[0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 168.63.129.16/32
              198.18.0.0/15 224.0.0.0/4 2000::/3 2001::/23 2001:db8::/32
              3fff::/20]

    def cidrs, do: @cidrs

    for cidr <- @cidrs do
      range = InetCidr.parse_cidr!(cidr)
      {elements, guard} = Ranges.__clause__(range)

      def within?(unquote(cidr), {unquote_splicing(elements)})
          when unquote(guard) do
        true
      end
    end

    def within?(_cidr, _address), do: false
  end

  describe "__clause__/1" do
    test "returns four variables for an IPv4 range" do
      range = InetCidr.parse_cidr!("10.0.0.0/8")
      {elements, _guard} = Ranges.__clause__(range)
      assert length(elements) == 4
    end

    test "returns eight variables for an IPv6 range" do
      range = InetCidr.parse_cidr!("2001:db8::/32")
      {elements, _guard} = Ranges.__clause__(range)
      assert length(elements) == 8
    end

    test "accepts an address inside the range" do
      assert Clauses.within?("10.0.0.0/8", {10, 0, 0, 0})
      assert Clauses.within?("10.0.0.0/8", {10, 255, 255, 255})
      assert Clauses.within?("100.64.0.0/10", {100, 100, 1, 1})
      assert Clauses.within?("168.63.129.16/32", {168, 63, 129, 16})
      assert Clauses.within?("2001:db8::/32", {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1})
    end

    test "refuses an address outside the range" do
      refute Clauses.within?("10.0.0.0/8", {9, 255, 255, 255})
      refute Clauses.within?("10.0.0.0/8", {11, 0, 0, 0})
      refute Clauses.within?("100.64.0.0/10", {100, 63, 255, 255})
      refute Clauses.within?("100.64.0.0/10", {100, 128, 0, 0})
      refute Clauses.within?("168.63.129.16/32", {168, 63, 129, 17})
      refute Clauses.within?("2001:db8::/32", {0x2001, 0xDB9, 0, 0, 0, 0, 0, 0})
    end

    test "constrains the trailing elements, not only the leading ones" do
      refute Clauses.within?("168.63.129.16/32", {168, 63, 0, 0})
      refute Clauses.within?("168.63.129.16/32", {168, 63, 129, 0})
      refute Clauses.within?("2001:db8::/32", {0x2001, 0, 0, 0, 0, 0, 0, 0})
    end

    test "agrees with InetCidr.contains?/2 on every boundary" do
      for cidr <- Clauses.cidrs() do
        range = InetCidr.parse_cidr!(cidr)

        for address <- boundaries(range) do
          assert Clauses.within?(cidr, address) ==
                   InetCidr.contains?(range, address),
                 "#{cidr} disagreed on #{:inet.ntoa(address)}"
        end
      end
    end
  end

  defp boundaries({first, last, _prefix}) do
    [first, last] ++ neighbours(first) ++ neighbours(last)
  end

  # neighbours({100, 64, 0, 0})
  #  [{99, 64, 0, 0}, {101, 64, 0, 0}, {100, 63, 0, 0}, {100, 65, 0, 0},
  #   {100, 64, 1, 0}, {100, 64, 0, 1}]
  defp neighbours(address) do
    ceiling = if tuple_size(address) == 4, do: 0xFF, else: 0xFFFF

    for {element, index} <- Enum.with_index(Tuple.to_list(address)),
        step <- [-1, 1],
        (element + step) in 0..ceiling do
      put_elem(address, index, element + step)
    end
  end
end
