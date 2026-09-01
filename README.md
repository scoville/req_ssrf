# ReqSSRF

ReqSSRF is a [Req](https://hex.pm/packages/req) plugin for SSRF protection.

## Installation

Add `req_ssrf` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:req_ssrf, "~> 0.1.0"}
  ]
end
```

## Requirements

ReqSSRF runs on the currently supported
[Elixir versions](https://elixir.hexdocs.pm/compatibility-and-deprecations.html)
and the compatible
[OTP versions](https://elixir.hexdocs.pm/compatibility-and-deprecations.html#between-elixir-and-erlang-otp).
OTP 24 is not supported, because Finch uses an option that was introduced in
OTP 25.

Versions older than the ones the CI matrix covers may still work, but they are
not covered by CI and not officially supported.

## Server Side Request Forgery

A server that fetches a URL an outsider supplied can be pointed at the network
it sits in rather than at the internet: another service, a database admin
page, or the cloud provider's metadata endpoint. This is Server Side Request
Forgery. For more information, refer to
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html.

## Usage

Attach the plugin to the request rather than checking the URL yourself:

```elixir
Req.new()
|> ReqSSRF.attach()
|> Req.get(url: submitted_url)
```

`ReqSSRF.attach/2` adds the check as a request step. `Req` follows redirects
by default, and it re-runs the request steps for each redirect, which means
that every hop is checked. Checking only the URL you were given is not enough:
a host that passes that check can respond with
`302 Location: http://169.254.169.254/` to point the server at an internal
endpoint.

For a URL that may not be fetched, `Req.request/2` returns
`{:error, %ReqSSRF.BlockedError{}}` and `Req.request!/2` raises it. The error
names the URL and the reason.

Attach the plugin after any other plugin that can change the URL.

`ReqSSRF.check/2` and `ReqSSRF.allowed?/2` check a single URL. Only use them
when you are not making the request, for example if you are validating a URL
the user is saving. Check it again using `ReqSSRF.attach/2` when you make an
HTTP request.

### Options

`ReqSSRF.attach/2` takes three options:

- `:schemes` - the accepted URL schemes. Defaults to `["http", "https"]`.
- `:allow_ip_address` - whether a host written as an IP address is accepted.
  Defaults to `true`.
- `:timeout` - how long to wait for a name to resolve, in milliseconds, or
  `:infinity`. Defaults to `2000`.

They are stored under the single `:ssrf_check` request option. Pass
`ssrf_check: false` on a request to skip the check.

### Tests

The check runs before the adapter, so it also runs when `Req.Test` has
replaced the adapter with a stub, and a stub on `http://localhost` is refused
like any other reserved address. Pass `ssrf_check: false` on those requests,
or give them a URL that resolves publicly.

## What the check does

- The scheme has to be `http` or `https`, so `file:`, `gopher:` and the rest
  are refused. Pass `:schemes` to set a different list, such as `["https"]`.
- A host written as an IP address is matched against the IANA reserved ranges
  in whatever notation it is written, so `127.0.0.1`, `2130706433`,
  `0177.0.0.1` and `[::ffff:127.0.0.1]` are all refused. Pass
  `allow_ip_address: false` to refuse literal hosts outright.
- A name is resolved with `:inet.getaddrs/2` for both address families, and
  every address in the answer has to be one the internet can route to.
- A host that does not resolve is refused.
- The check reads more addresses than the request uses. `Req` connects over
  IPv4 unless you configure it otherwise, but the check reads the AAAA records
  too. A name whose A record is public and whose AAAA record is reserved is
  refused.

## What the check does not do

The addresses are checked, and then the host is resolved again when the
connection is made. A resolver under the attacker's control can answer
differently the second time, so a name that passed can still connect to a
reserved address. This is DNS rebinding. It needs a nameserver the attacker
controls, while the redirect that `ReqSSRF.attach/2` closes needs only one
response header.

The library does not close it. Closing it in the application means connecting
to the validated address while keeping the `Host` header, the TLS server name
and the certificate hostname check, and getting any of the three wrong turns
certificate verification off without saying so.

Using the check therefore means accepting that a host whose DNS the attacker
controls can reach any address the server routes to. Deny egress to the
private ranges and the metadata endpoint at the network if that is not
acceptable. That also covers the fetches nobody remembered to check, which
this library cannot.

The check mostly cannot tell a failed lookup from a missing record. A resolver
that refuses and a name that has no record of that family both come back as
`:nxdomain`, because OTP collapses every error into that one reason. So a
family whose lookup failed looks like a family with no addresses, and the check
rests on what the other family answered. A name whose A lookup fails and whose
AAAA record is public passes the check, and the request then connects over the
A record, which nothing checked. The mitigation is the same as for DNS
rebinding.

The exception is the `:timeout`, which the library imposes itself and can
therefore recognise. A lookup that misses that deadline is refused with
`:resolution_failed` rather than being read as a family with no records.

## What else the check leaves open

Nothing connects to a refused URL, so a user cannot find out what is listening
on an internal address. Two things remain.

The first is the reason for a refusal. `ReqSSRF.BlockedError` says whether the
name failed to resolve or resolved to a reserved address, which tells a user
which names your resolver knows and a public one does not: inside a VPC,
submitting `db.internal` reveals whether it exists. Do not show the reason to
whoever supplied the URL.

The second is the fetch itself. A user learns little from a URL that passes,
since they can reach a public host without your help, but the request goes out
from your server's address rather than theirs. Yours is the address in the
target's logs and the one blocked for abuse, and a service that allowlists
your IP range will take a request from your server that it would refuse from
the user. Rate limit the paths that fetch on a user's behalf.

## Open redirects

Whether the server may fetch a URL and whether the browser may redirect to one
are different questions, and this library answers only the first. Do not use
`ReqSSRF.check/2` to validate a redirect target.
