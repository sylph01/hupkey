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
KEM_ID = 18
KDF_ID = 3
AEAD_ID = 2
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
  OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data)
end

def extract(salt, ikm)
  hmac_hash(salt, ikm)
end

# TODO: n > 255
def expand(prk, info, l)
  n = (l.to_f / OpenSSL::Digest.new('SHA512').digest_length).ceil
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

  n_secret = 64 # P-521 uses 64, based on section 4.1
  labeled_expand(eae_prk, 'shared_secret', kem_context, n_secret, suite_id)
end

def generate_key_pair
  OpenSSL::PKey::EC.generate('secp521r1')
  # derive_key_pair(SecureRandom.random_bytes(65))
end

def derive_key_pair_from_num(n)
  derive_key_pair(OpenSSL::BN.new(n).to_s(2))
end

def derive_key_pair(ikm)
  asn1_seq = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Integer(1),
    OpenSSL::ASN1.OctetString(ikm),
    OpenSSL::ASN1.ObjectId('secp521r1', 0, :EXPLICIT)
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
      OpenSSL::ASN1.ObjectId('secp521r1')
    ]),
    OpenSSL::ASN1.BitString(serialized_pk)
  ])

  OpenSSL::PKey.read(asn1_seq.to_der)
end

def encap(pk_r)
  pkey_e = generate_key_pair()
  dh = pkey_e.dh_compute_key(pk_r)
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

def decap(enc, sk_r)
  pk_e = deserialize_public_key(enc)
  dh = sk_r.dh_compute_key(pk_e.public_key)

  pkrm = serialize_public_key(sk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  shared_secret
end

def verify_psk_inputs(mode, psk, psk_id)
  got_psk = (psk != DEFAULT_PSK)
  got_psk_id = (psk_id != DEFAULT_PSK_ID)

  raise Exception('Inconsistent PSK inputs') if got_psk != got_psk_id
  raise Exception('PSK input provided when not needed') if got_psk && [MODE_BASE, MODE_AUTH].include?(mode)
  raise Exception('Missing required PSK input') if !got_psk && [MODE_PSK, MODE_AUTH_PSK].include?(mode)

  true
end

def key_schedule(mode, shared_secret, info, psk = '', psk_id = '')
  verify_psk_inputs(mode, psk, psk_id)

  psk_id_hash = labeled_extract('', 'psk_id_hash', psk_id, HPKE_SUITE_ID)
  info_hash = labeled_extract('', 'info_hash', info, HPKE_SUITE_ID)
  key_schedule_context = mode.chr + psk_id_hash + info_hash

  puts key_schedule_context.unpack1('H*')

  secret = labeled_extract(shared_secret, 'secret', psk, HPKE_SUITE_ID)

  key = labeled_expand(secret, 'key', key_schedule_context, 32, HPKE_SUITE_ID) # Nk
  base_nonce = labeled_expand(secret, 'base_nonce', key_schedule_context, 12, HPKE_SUITE_ID) # Nn
  exporter_secret = labeled_expand(secret, 'exp', key_schedule_context, 64, HPKE_SUITE_ID) # Nh

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
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
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
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = key
  cipher.iv = nonce
  cipher.auth_tag = tag
  cipher.auth_data = aad
  cipher.padding = 0
  cipher.update(ct_body) << cipher.final
end

pkem = '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'
pkrm = '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64'
skem = '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b'
skrm = '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847'
ikme = '7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904'
shared_secret = '776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818'
info = '4f6465206f6e2061204772656369616e2055726e'
key = '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70'
exporter_secret = 'e4ff9dfbc732a2b9c75823763c5ccc954a2c0648fc6de80a58581252d0ee3215388a4455e69086b50b87eb28c169a52f42e71de4ca61c920e7bd24c95cc3f992'
base_nonce = '55ff7a7d739c69f44b25447b'

p hex_to_str(key).length
p hex_to_str(base_nonce).length
p hex_to_str(exporter_secret).length

pkr = deserialize_public_key(hex_to_str(pkrm))
encap_result = encap_fixed(pkr, skem)
puts 'encap:'
puts encap_result[:shared_secret].unpack1('H*')
puts encap_result[:enc].unpack1('H*')
skr = derive_key_pair(hex_to_str(skrm))
decapped_secret = decap(encap_result[:enc], skr)
puts 'decap:'
puts decapped_secret.unpack1('H*')

key_schedule = key_schedule_s(MODE_BASE, hex_to_str(shared_secret), hex_to_str(info))

puts 'key_schedule key, base_nonce, exporter_secret:'
puts key_schedule[:key].unpack1('H*')
puts key_schedule[:base_nonce].unpack1('H*')
puts key_schedule[:exporter_secret].unpack1('H*')
puts 'key_schedule key, base_nonce, exporter_secret (expected):'
puts key, base_nonce, exporter_secret
puts ''

aad = '436f756e742d30'
pt  = '4265617574792069732074727574682c20747275746820626561757479'
ct  = '170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a'

puts "ciphertext(got), ciphertext(expected):"
puts cipher_seal([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [pt].pack('H*')).unpack1('H*')
puts ct
puts ''

puts "plaintext(got), plaintext(expected):"
puts cipher_open([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [ct].pack('H*')).unpack1('H*')
puts pt
