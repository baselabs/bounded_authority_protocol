import Config

# Self-enforcing toolchain floor (ADR 0031). Evaluated at config-load time, before
# compilation, for every Mix invocation in this repository. NOT shipped in the Hex
# package (`files:` in mix.exs carries no `config/`), so consumers of the published
# package never inherit this assert; each consuming repository enforces its own
# toolchain. OTP 27 is the floor because lib/bounded_authority_protocol/v1/json.ex
# decodes through the stdlib :json module (OTP 27+). :erlang.system_info(:otp_release)
# returns a charlist — to_string/1 is required or the membership test always fails.
supported_otp = ["27", "28", "29"]
running_otp = to_string(:erlang.system_info(:otp_release))

unless running_otp in supported_otp do
  raise(
    "bounded_authority_protocol supports Erlang/OTP #{Enum.join(supported_otp, "/")}; " <>
      "running #{running_otp} (Elixir #{System.version()}, code root #{:code.root_dir()})."
  )
end
