module Envelope.Spec

open FStar.Bytes
open FStar.Seq

type envelope_version = v:nat{v = 1}

type envelope = {
  ver: envelope_version;
  tenant_id: seq byte;
  policy_id: seq byte;
  path: seq byte;
  ts_epoch_ms: nat;
  nonce: b:seq byte{length b = 12};
  kem_ct: seq byte;
  sig: seq byte;
  ct: seq byte;
}

val envelope_parse_total:
  input:seq byte ->
  Tot (option envelope)
  (decreases (length input))

val envelope_encode:
  env:envelope ->
  Tot (seq byte)

val round_trip_lemma:
  env:envelope ->
  Lemma (ensures (
    match envelope_parse_total (envelope_encode env) with
    | Some env' -> env == env'
    | None -> False
  ))
