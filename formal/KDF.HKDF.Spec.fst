module KDF.HKDF.Spec

open FStar.Seq
open FStar.Bytes

val hkdf_extract:
  salt:seq byte ->
  ikm:seq byte ->
  Tot (prk:seq byte{length prk = 32})

val hkdf_expand:
  prk:seq byte{length prk = 32} ->
  info:seq byte ->
  output_len:nat{output_len <= 255 * 32} ->
  Tot (output:seq byte{length output = output_len})

val domain_separation_lemma:
  ikm:seq byte ->
  salt:seq byte ->
  info1:seq byte ->
  info2:seq byte ->
  len:nat{len <= 255 * 32} ->
  Lemma (requires (info1 <> info2))
        (ensures (
          let prk = hkdf_extract salt ikm in
          hkdf_expand prk info1 len <> hkdf_expand prk info2 len
        ))
