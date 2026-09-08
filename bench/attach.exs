# mix run bench/attach.exs

deny = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]

request = ReqSSRF.attach(Req.new(url: "http://93.184.216.34/"))
blocked = ReqSSRF.attach(Req.new(url: "http://127.0.0.1/"))
denied = ReqSSRF.attach(Req.new(url: "http://93.184.216.34/"), deny: deny)
skipped = Req.merge(request, ssrf_check: false)
overridden = Req.merge(request, ssrf_check: [deny: deny])

run_step = fn %Req.Request{request_steps: steps} = req ->
  {:ssrf_check, step} = List.keyfind(steps, :ssrf_check, 0)
  step.(req)
end

Benchee.run(
  %{
    "attach/2" => fn -> ReqSSRF.attach(Req.new()) end,
    "attach/2, three deny ranges" => fn ->
      ReqSSRF.attach(Req.new(), deny: deny)
    end,
    "step, allowed" => fn -> run_step.(request) end,
    "step, blocked" => fn -> run_step.(blocked) end,
    "step, skipped" => fn -> run_step.(skipped) end,
    "step, three attached deny ranges" => fn -> run_step.(denied) end,
    "step, overridden" => fn -> run_step.(overridden) end
  },
  warmup: 1,
  time: 3,
  memory_time: 1,
  reduction_time: 1
)
