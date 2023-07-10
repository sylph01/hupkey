# note: Use test vectors A3, P-256, HKDF-SHA256, HKDF-SHA256, AES-128-GCM

require 'openssl'
require 'securerandom'

def i2osp(n, w)
  # check n > 0 and n < 256 ** w
  ret = []
  for i in 0..(w-1)
    ret[w - (i + 1)] = n % 256
    n = n >> 8
  end
  ret.map(&:chr).join
end

def os2ip(x)
  x.chars.map(&:ord).reduce {|a, b| a * 256 + b}
end

DEFAULT_PSK = ''
DEFAULT_PSK_ID = ''
MODE_BASE     = 0x00
MODE_PSK      = 0x01
MODE_AUTH     = 0x02
MODE_AUTH_PSK = 0x03
KEM_ID = 16
KDF_ID = 1
AEAD_ID = 1
KEM_SUITE_ID  = 'KEM' + i2osp(KEM_ID, 2)
HPKE_SUITE_ID = 'HPKE' + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)

def xor(a, b)
  if a.length != b.length
    return false
  end
  c = ""
  for i in 0 .. (a.length - 1)
    c += (a[i].ord ^ b[i].ord).chr
  end
  c
end

def hex_to_str(hex)
  hex = hex.slice(2..-1) if hex.start_with?('0x')
  [hex].pack('H*')
end

def hmac_hash(key, data)
  OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), key, data)
end

def extract(salt, ikm)
  hmac_hash(salt, ikm)
end

# TODO: n > 255
def expand(prk, info, l)
  n = (l.to_f / OpenSSL::Digest.new('SHA256').digest_length).ceil
  t = ['']
  for i in 0 .. n do
    t << hmac_hash(prk, t[i] + info + (i + 1).chr)
  end
  t_concat = t.join
  t_concat[0..l-1]
end

def labeled_extract(salt, label, ikm, suite_id)
  labeled_ikm = 'HPKE-v1' + suite_id + label + ikm
  extract(salt, labeled_ikm)
end

def labeled_expand(prk, label, info, l, suite_id)
  labeled_info = i2osp(l, 2) + 'HPKE-v1' + suite_id + label + info
  expand(prk, labeled_info, l)
end

def extract_and_expand(dh, kem_context, suite_id)
  eae_prk = labeled_extract('', 'eae_prk', dh, suite_id)

  n_secret = 32 # this is based on length of SHA-256, which is 32 bytes
  labeled_expand(eae_prk, 'shared_secret', kem_context, n_secret, suite_id)
end

def generate_key_pair
  # OpenSSL::PKey::EC.generate('prime256v1')
  derive_key_pair(SecureRandom.random_bytes(32))
end

def derive_key_pair_from_num(n)
  derive_key_pair(OpenSSL::BN.new(n).to_s(2))
end

def derive_key_pair(ikm)
  asn1_seq = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Integer(1),
    OpenSSL::ASN1.OctetString(ikm),
    OpenSSL::ASN1.ObjectId('prime256v1', 0, :EXPLICIT)
  ])

  OpenSSL::PKey.read(asn1_seq.to_der)
end

def serialize_public_key(pk)
  pk.public_key.to_bn.to_s(2)
  # pk.public_key.to_bn.to_s(16).downcase
end

def deserialize_public_key(serialized_pk)
  asn1_seq = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId("id-ecPublicKey"),
      OpenSSL::ASN1.ObjectId('prime256v1')
    ]),
    OpenSSL::ASN1.BitString(serialized_pk)
  ])

  OpenSSL::PKey.read(asn1_seq.to_der)
end

def encap(pk_r)
  pkey_e = generate_key_pair()
  dh = pkey_e.dh_compute_key(pk_r.public_key)
  enc = serialize_public_key(pkey_e)

  pkrm = serialize_public_key(pk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  {
    shared_secret: shared_secret,
    enc: enc
  }
end

def encap_fixed(pk_r, ikm_e)
  pkey_e = derive_key_pair(hex_to_str(ikm_e))
  dh = pkey_e.dh_compute_key(pk_r.public_key)
  enc = serialize_public_key(pkey_e)

  pkrm = serialize_public_key(pk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  {
    shared_secret: shared_secret,
    enc: enc
  }
end

def auth_encap(pk_r, sk_s)
  pkey_e = generate_key_pair()
  dh = pkey_e.dh_compute_key(pk_r.public_key) + sk_s.dh_compute_key(pk_r.public_key)
  enc = serialize_public_key(pkey_e)

  pkrm = serialize_public_key(pk_r)
  pksm = serialize_public_key(sk_s)
  kem_context = enc + pkrm + pksm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  {
    shared_secret: shared_secret,
    enc: enc
  }
end

def auth_encap_fixed(pk_r, sk_s, ikm_e)
  pkey_e = derive_key_pair(hex_to_str(ikm_e))
  dh = pkey_e.dh_compute_key(pk_r.public_key) + sk_s.dh_compute_key(pk_r.public_key)
  enc = serialize_public_key(pkey_e)

  pkrm = serialize_public_key(pk_r)
  pksm = serialize_public_key(sk_s)
  kem_context = enc + pkrm + pksm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  {
    shared_secret: shared_secret,
    enc: enc
  }
end

def decap(enc, sk_r)
  pk_e = deserialize_public_key(enc)
  dh = sk_r.dh_compute_key(pk_e.public_key)

  pkrm = serialize_public_key(sk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  shared_secret
end

def auth_decap(enc, sk_r, pk_s)
  pk_e = deserialize_public_key(enc)
  dh = sk_r.dh_compute_key(pk_e.public_key) + sk_r.dh_compute_key(pk_s.public_key)

  pkrm = serialize_public_key(sk_r)
  pksm = serialize_public_key(pk_s)
  kem_context = enc + pkrm + pksm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  shared_secret
end

def verify_psk_inputs(mode, psk, psk_id)
  got_psk = (psk != DEFAULT_PSK)
  got_psk_id = (psk_id != DEFAULT_PSK_ID)

  raise Exception.new('Inconsistent PSK inputs') if got_psk != got_psk_id
  raise Exception.new('PSK input provided when not needed') if got_psk && [MODE_BASE, MODE_AUTH].include?(mode)
  raise Exception.new('Missing required PSK input') if !got_psk && [MODE_PSK, MODE_AUTH_PSK].include?(mode)

  true
end

def key_schedule(mode, shared_secret, info, psk = '', psk_id = '')
  verify_psk_inputs(mode, psk, psk_id)

  psk_id_hash = labeled_extract('', 'psk_id_hash', psk_id, HPKE_SUITE_ID)
  info_hash = labeled_extract('', 'info_hash', info, HPKE_SUITE_ID)
  key_schedule_context = mode.chr + psk_id_hash + info_hash

  secret = labeled_extract(shared_secret, 'secret', psk, HPKE_SUITE_ID)

  key = labeled_expand(secret, 'key', key_schedule_context, 16, HPKE_SUITE_ID) # Nk
  base_nonce = labeled_expand(secret, 'base_nonce', key_schedule_context, 12, HPKE_SUITE_ID) # Nn
  exporter_secret = labeled_expand(secret, 'exp', key_schedule_context, 32, HPKE_SUITE_ID) # Nh

  {
    type: nil,
    key: key,
    base_nonce: base_nonce,
    sequence_number: 0,
    exporter_secret: exporter_secret
  }
end

def key_schedule_s(mode, shared_secret, info, psk = '', psk_id = '')
  ks = key_schedule(mode, shared_secret, info, psk, psk_id)
  ks[:type] = :s
  ks
end

def key_schedule_r(mode, shared_secret, info, psk, psk_id)
  ks = key_schedule(mode, shared_secret, info, psk, psk_id)
  ks[:type] = :r
  ks
end

def cipher_seal(key, nonce, aad, pt)
  cipher = OpenSSL::Cipher.new('aes-128-gcm')
  cipher.encrypt
  cipher.key = key
  cipher.iv = nonce
  cipher.auth_data = aad
  cipher.padding = 0
  s = cipher.update(pt) << cipher.final
  s + cipher.auth_tag
end

def cipher_open(key, nonce, aad, ct)
  ct_body = ct[0, ct.length - 16] # TODO: tag length might vary based on GCM length
  tag = ct[-16, 16]
  cipher = OpenSSL::Cipher.new('aes-128-gcm')
  cipher.decrypt
  cipher.key = key
  cipher.iv = nonce
  cipher.auth_tag = tag
  cipher.auth_data = aad
  cipher.padding = 0
  cipher.update(ct_body) << cipher.final
end

pkem = '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'
pkrm = '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'
skem = '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'
skrm = 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'
ikme = '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e'
shared_secret = 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8'
info = '4f6465206f6e2061204772656369616e2055726e'
key = '868c066ef58aae6dc589b6cfdd18f97e'
exporter_secret = '14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f'

# p hex_to_str(key).length
# p hex_to_str(base_nonce).length
# p hex_to_str(exporter_secret).length

# pkr = deserialize_public_key(hex_to_str(pkrm))
# encap_result = encap_fixed(pkr, skem)
# puts 'encap:'
# puts encap_result[:shared_secret].unpack1('H*')
# puts encap_result[:enc].unpack1('H*')
# skr = derive_key_pair(hex_to_str(skrm))
# decapped_secret = decap(encap_result[:enc], skr)
# puts 'decap:'
# puts decapped_secret.unpack1('H*')

key_schedule = key_schedule_s(MODE_BASE, hex_to_str(shared_secret), hex_to_str(info))

puts key_schedule[:key].unpack1('H*')
puts key_schedule[:base_nonce].unpack1('H*')
puts key_schedule[:exporter_secret].unpack1('H*')

base_nonce = '4e0bc5018beba4bf004cca59'
aad = '436f756e742d30'
pt  = '4265617574792069732074727574682c20747275746820626561757479'
ct  = '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'

puts cipher_seal([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [pt].pack('H*')).unpack1('H*')
puts ct

puts cipher_open([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [ct].pack('H*')).unpack1('H*')
puts pt

puts ''
puts '----psk mode----'

pkem = '04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f'
pkrm = '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1'
skem = '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f'
skrm = '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661'
psk = '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82'
psk_id = '456e6e796e20447572696e206172616e204d6f726961'
shared_secret = '2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b'
key_schedule_context = '01b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85'
secret = 'f2f534e55931c62eeb2188c1f53450354a725183937e68c85e68d6b267504d26'
key = '55d9eb9d26911d4c514a990fa8d57048'
base_nonce = 'b595dc6b2d7e2ed23af529b1'
exporter_secret = '895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705'

pkr = deserialize_public_key(hex_to_str(pkrm))
encap_result = encap_fixed(pkr, skem)
puts 'encap:'
puts encap_result[:shared_secret].unpack1('H*')
puts ''
skr = derive_key_pair(hex_to_str(skrm))
decapped_secret = decap(encap_result[:enc], skr)
puts 'decap:'
puts decapped_secret.unpack1('H*')
puts ''
puts 'shared secret:'
puts shared_secret
puts ''

key_schedule = key_schedule_s(MODE_PSK, hex_to_str(shared_secret), hex_to_str(info), hex_to_str(psk), hex_to_str(psk_id))

puts 'key_schedule key, base_nonce, exporter_secret:'
puts key_schedule[:key].unpack1('H*')
puts key_schedule[:base_nonce].unpack1('H*')
puts key_schedule[:exporter_secret].unpack1('H*')
puts 'key_schedule key, base_nonce, exporter_secret (expected):'
puts key, base_nonce, exporter_secret
puts ''

puts ''
puts '----auth mode----'

pkem = '042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454'
skem = '6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91'
pkrm = '04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d'
skrm = 'd929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e'
pksm = '04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73'
sksm = '1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9'
shared_secret = 'd4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f'
key = '19aa8472b3fdc530392b0e54ca17c0f5'
base_nonce = 'b390052d26b67a5b8a8fcaa4'
exporter_secret = 'f152759972660eb0e1db880835abd5de1c39c8e9cd269f6f082ed80e28acb164'

pkr = deserialize_public_key(hex_to_str(pkrm))
sks = derive_key_pair(hex_to_str(sksm))

encap_result = auth_encap_fixed(pkr, sks, skem)

puts 'encap:'
puts encap_result[:shared_secret].unpack1('H*')
puts ''

skr = derive_key_pair(hex_to_str(skrm))
pks = deserialize_public_key(hex_to_str(pksm))
decapped_secret = auth_decap(encap_result[:enc], skr, pks)

puts 'decap:'
puts decapped_secret.unpack1('H*')
puts ''
puts 'shared secret:'
puts shared_secret
puts ''

key_schedule = key_schedule_s(MODE_AUTH, hex_to_str(shared_secret), hex_to_str(info))

puts 'key_schedule key, base_nonce, exporter_secret:'
puts key_schedule[:key].unpack1('H*')
puts key_schedule[:base_nonce].unpack1('H*')
puts key_schedule[:exporter_secret].unpack1('H*')
puts 'key_schedule key, base_nonce, exporter_secret (expected):'
puts key, base_nonce, exporter_secret
puts ''