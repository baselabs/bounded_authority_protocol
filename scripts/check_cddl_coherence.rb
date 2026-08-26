#!/usr/bin/env ruby
# CDDL/corpus coherence (informative CDDL, CI job).
#
# Proves the informative CDDL summary (spec/cddl/bap-v1.cddl) stays coherent with the
# conformance corpus: every valid case's CDDL-covered artifact validates, and a fixed set of
# CDDL-expressible invalid exemplars rejects. The corpus remains the sole machine-checked
# authority; CDDL inexpressibility (duplicate names, exact canonical bytes, tagged
# integer/float distinction, binary framing) is out of scope BY DESIGN and recorded in the
# CDDL's header comment.

require "json"
require "base64"
require "cddl"

ROOT = File.expand_path("..", __dir__)
CORPUS = File.join(ROOT, "priv/conformance/v1/corpus")

CDDL_SOURCE = File.read(File.join(ROOT, "spec/cddl/bap-v1.cddl"))

# The gem validates against a grammar's FIRST rule; per-family parsers prepend a target rule.
PARSERS = {}
%w[bap-grant-payload bap-proof-payload bap-consumption-row bap-boundary-anchor-payload
   bap-key-transition-payload].each do |rule|
  PARSERS[rule] = CDDL::Parser.new("target = #{rule}\n" + CDDL_SOURCE)
end

def cddl_valid?(rule, data)
  result = PARSERS.fetch(rule).validate(data, false)
  !result.nil?
end

def b64u(str)
  return "" if str.nil? || str.empty?

  pad = str.length % 4 == 0 ? "" : "=" * (4 - str.length % 4)
  Base64.urlsafe_decode64(str + pad)
end

def compact_parts(compact)
  parts = compact.split(".")
  return nil unless parts.size == 3 && !parts[0].empty?

  head = JSON.parse(b64u(parts[0]))
  return nil unless head.is_a?(Hash)

  payload_text = b64u(parts[1])
  return [head, nil] if payload_text.empty?

  [head, JSON.parse(payload_text)]
rescue JSON::ParserError, ArgumentError
  nil
end

# ---- load corpus cases --------------------------------------------------------

cases = []
Dir[File.join(CORPUS, "cases/**/*.json")].sort.each do |path|
  file = JSON.parse(File.read(path))
  file["cases"].each { |c| cases << c }
end

valid = cases.select { |c| c.dig("expected", "verdict") == "valid" }

checked = 0
failures = []

# Grant/proof headers and payloads of every valid case carrying a compact.
valid.each do |c|
  input = c["input"]
  compact = input["compact"] || input["grant"] || input["proof"]
  next unless compact.is_a?(String)

  parts = compact_parts(compact)
  next unless parts

  header, payload = parts
  rule = case header.dig("typ")
         when "ba+cap" then "bap-grant-payload"
         when "dpop+jwt" then "bap-proof-payload"
         when "ba+chain-anchor" then "bap-boundary-anchor-payload"
         when "ba+key-transition" then "bap-key-transition-payload"
         else next
         end

  checked += 1
  failures << "#{c['id']}: #{rule} rejected" unless cddl_valid?(rule, payload)
end

# Consumption rows of every valid chain case carrying base64url rows.
valid.each do |c|
  rows = c.dig("input", "rows")
  next unless rows.is_a?(Array) && !rows.empty?

  rows.each_with_index do |row, i|
    decoded = JSON.parse(b64u(row))
    checked += 1
    failures << "#{c['id']}[#{i}]: row rejected" unless cddl_valid?("bap-consumption-row", decoded)
  rescue JSON::ParserError, ArgumentError
    failures << "#{c['id']}[#{i}]: row not decodable"
  end
end

raise "no valid cases exercised the CDDL (#{failures.join('; ')})" if checked.zero?

# ---- CDDL-expressible invalid exemplars must REJECT ---------------------------
#
# A PINNED list: each exemplar's violation is expressible in CDDL (a regexp or a closed member
# set the CDDL types). If the corpus evolves and renames one, this leg fails loudly instead of
# going vacuous — the pinned list is the non-vacuity proof.

REJECT_EXEMPLARS = {
  # htm carries a space (0x20 outside the printable-token range the CDDL regexp pins).
  "decode-proof-invalid-encoding-method-token" => :payload,
  # ba_inv is not a lowercase UUID (regexp).
  "decode-proof-invalid-encoding-invocation-not-uuid" => :payload,
  # nonce is present but empty (size bound 1..512).
  "decode-proof-invalid-encoding-nonce-empty" => :payload,
  # Protected header alg is "none" (closed header member set).
  "grant-decode-invalid-algorithm-none" => :header
}.freeze

by_id = cases.to_h { |c| [c["id"], c] }

REJECT_EXEMPLARS.each do |id, target|
  c = by_id[id]
  raise "reject exemplar #{id} missing from the corpus — re-pin the coherence leg" unless c

  parts = compact_parts(c["input"]["compact"])
  raise "reject exemplar #{id} carries no decodable compact" unless parts

  header, payload = parts
  if target == :header
    rule = header.dig("typ") == "dpop+jwt" ? "bap-proof-header" : "bap-grant-header"
    parser = CDDL::Parser.new("target = #{rule}\n" + CDDL_SOURCE)
    raise "#{id}: CDDL-expressible invalid header ACCEPTED" if parser.validate(header, false)
  elsif cddl_valid?(payload.key?("operations") ? "bap-grant-payload" : "bap-proof-payload", payload)
    raise "#{id}: CDDL-expressible invalid payload ACCEPTED"
  end
end

if failures.any?
  warn "cddl coherence FAILED:\n  #{failures.join("\n  ")}"
  exit 1
end

puts "cddl coherence: ok valid=#{checked} reject-exemplars=#{REJECT_EXEMPLARS.size}"
