defmodule BoundedAuthorityProtocol.RenderDerived do
  # Derived-view generator (spec-decoupling L3, ticket 09). docs/protocol-v1.md is no longer
  # authored: it is a GENERATED package-facing view of the normative authority spec/bap-v1.md.
  # The derivation is mechanical and byte-deterministic: strip the kramdown-rfc front matter,
  # normalize the citation syntax to plain-markdown references, and append the generation
  # footer naming the authority and its revision.
  #
  # Usage:
  #   mix run --no-start spec/tools/render_derived.exs          # check: committed == rebuilt
  #   mix run --no-start spec/tools/render_derived.exs --write  # regenerate the view

  @root Path.expand("../..", __DIR__)
  @source "spec/bap-v1.md"
  @target "docs/protocol-v1.md"
  @spec_revision 1

  def run(argv) do
    rendered = render()

    case argv do
      ["--write"] ->
        File.write!(Path.join(@root, @target), rendered)
        IO.puts("render_derived: rewrote #{@target} (#{byte_size(rendered)} bytes)")

      _ ->
        current = File.read!(Path.join(@root, @target))

        if current == rendered do
          IO.puts("render_derived: #{@target} matches the rebuild (#{byte_size(rendered)} bytes)")
        else
          IO.puts(:stderr, "render_derived: #{@target} does NOT match the rebuild — hand edits are forbidden; regenerate with --write")
          System.halt(1)
        end
    end
  end

  def render do
    source = File.read!(Path.join(@root, @source))

    body =
      source
      |> strip_front_matter()
      |> normalize_citations()
      |> String.trim_trailing()

    header =
      "<!-- DERIVED VIEW — generated from spec/bap-v1.md; DO NOT EDIT.\n" <>
        "     Regenerate: mix run --no-start spec/tools/render_derived.exs --write -->\n\n"

    footer = "\n\n---\n\nGenerated from `spec/bap-v1.md` rev #{@spec_revision} (the single normative authority).\n"

    header <> body <> footer
  end

  defp strip_front_matter(text) do
    case String.split(text, "---", parts: 3) do
      ["", _front, rest] -> rest |> String.trim_leading("\n")
      _ -> text
    end
  end

  defp normalize_citations(text) do
    Regex.replace(~r/\[@RFC(\d+)\]/, text, "[RFC\\1]")
  end
end

BoundedAuthorityProtocol.RenderDerived.run(System.argv())
