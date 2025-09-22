module Verify.Path.Spec

open FStar.Seq

type policy = {
  tenant_id: seq byte;
  policy_id: seq byte;
  path: seq byte;
  required_algs: seq byte;
  max_age_ms: nat;
}

type decision = | Accept | Reject

val verify_predicates:
  envelope_tenant:seq byte ->
  envelope_policy:seq byte ->
  envelope_path:seq byte ->
  envelope_algs:seq byte ->
  envelope_ts:nat ->
  policy:policy ->
  now_ms:nat ->
  Tot decision

val soundness_lemma:
  e_tenant:seq byte ->
  e_policy:seq byte ->
  e_path:seq byte ->
  e_algs:seq byte ->
  e_ts:nat ->
  pol:policy ->
  now:nat ->
  Lemma (ensures (
    verify_predicates e_tenant e_policy e_path e_algs e_ts pol now = Accept <==>
    (e_tenant == pol.tenant_id /\
     e_policy == pol.policy_id /\
     e_path == pol.path /\
     e_algs == pol.required_algs /\
     now - e_ts <= pol.max_age_ms)
  ))
