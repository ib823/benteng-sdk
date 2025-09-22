module AAD.Binding

open FStar.Seq
open FStar.Bytes

type aad = {
  ver: nat;
  tenant_id: seq byte;
  policy_id: seq byte;
  path: seq byte;
  ts_epoch_ms: nat;
  required_algs: seq byte;
  hybrid: bool;
  device_attest_hash: option (seq byte);
}

val aad_build:
  ver:nat ->
  tenant_id:seq byte ->
  policy_id:seq byte ->
  path:seq byte ->
  ts_epoch_ms:nat ->
  required_algs:seq byte ->
  hybrid:bool ->
  device_attest_hash:option (seq byte) ->
  Tot aad

val aad_to_bytes:
  a:aad ->
  Tot (seq byte)

val aad_injectivity_lemma:
  a1:aad -> a2:aad ->
  Lemma (requires (aad_to_bytes a1 == aad_to_bytes a2))
        (ensures (a1 == a2))
