# mix run bench/public_address.exs

Benchee.run(
  %{
    "ipv4, public" => fn -> ReqSSRF.public_address?({93, 184, 216, 34}) end,
    "ipv4, first range" => fn -> ReqSSRF.public_address?({0, 0, 0, 1}) end,
    "ipv4, last range" => fn -> ReqSSRF.public_address?({240, 0, 0, 1}) end,
    "ipv6, public" => fn ->
      ReqSSRF.public_address?(
        {0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946}
      )
    end,
    "ipv6, outside global unicast" => fn ->
      ReqSSRF.public_address?({0xFD00, 0, 0, 0, 0, 0, 0, 1})
    end,
    "ipv4-mapped ipv6" => fn ->
      ReqSSRF.public_address?({0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE})
    end
  },
  warmup: 1,
  time: 3,
  memory_time: 1,
  reduction_time: 1
)
