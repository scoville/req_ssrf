# Contributing

Thanks for helping out. Issues and pull requests are both welcome.

## Security

Please do not open a public issue for a vulnerability. [SECURITY.md](SECURITY.md)
explains how to report one privately.

## Getting started

```bash
mix deps.get
mix test
```

Some tests resolve real host names, so you need network access to run the suite.

## Running the checks

Run what CI runs before you push:

```bash
mix format
mix compile --warnings-as-errors
mix credo
mix test --warnings-as-errors
mix docs --warnings-as-errors
mix dialyzer
```

The first `mix dialyzer` builds a PLT and takes a few minutes. After that it is
quick.

Three things fail the build and are easy to miss:

- Test coverage has to stay at 100%. `mix coveralls.html` writes an HTML
  coverage report.
- Both `mix compile --warnings-as-errors` and `mix test --warnings-as-errors`
  have to complete without error on the latest Elixir and OTP versions.
- Lines wrap at 80 characters.

CI also runs the suite across every supported Elixir and OTP pair.

## Pull requests

For a new feature, or a change to how an existing one behaves, please open an
issue first so we can agree on the shape before you write it. For bug fixes,
documentation and typo fixes, you can open a PR directly.

If an issue exists, reference it in the pull request, for example
`resolves #123`. Add a test that covers the change, and for a bug fix one that
fails without it. Add a changelog entry if the change is user-facing.

Commit messages follow no particular convention. Keep the first line under 72
characters, write it in the present tense, and say what the commit does:
"add option to refuse literal IP addresses" rather than "added option" or
"fixes". The existing history is a reasonable guide.

## Changing what the check refuses

If you add or remove an IP range, link the source in the pull request: the IANA
registry entry, the cloud provider's documentation, or the RFC. The ranges are
the whole product, so a reviewer needs to check the source rather than take your
word for it.
