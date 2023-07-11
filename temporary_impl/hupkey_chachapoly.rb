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
KEM_ID = 32
KDF_ID = 1
AEAD_ID = 3
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
  derive_key_pair(SecureRandom.random_bytes(32))
end

def derive_key_pair(ikm)
  asn1_seq = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Integer(0),
    OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId('1.3.101.110')
    ]),
    OpenSSL::ASN1.OctetString("\x04\x20" + ikm)
  ])

  OpenSSL::PKey.read(asn1_seq.to_der)
end

def serialize_public_key(pk)
  pk.public_to_der[-32, 32]
end

def deserialize_public_key(serialized_pk)
  asn1_seq_pub = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId('1.3.101.110')
    ]),
    OpenSSL::ASN1.BitString(serialized_pk)
  ])

  OpenSSL::PKey.read(asn1_seq_pub.to_der)
end

def encap(pk_r)
  pkey_e = generate_key_pair()
  dh = pkey_e.derive(pk_r)
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
  dh = pkey_e.derive(pk_r)
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
  dh = sk_r.derive(pk_e)

  pkrm = serialize_public_key(sk_r)
  kem_context = enc + pkrm

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

  key = labeled_expand(secret, 'key', key_schedule_context, 32, HPKE_SUITE_ID) # Nk: ChaChaPoly uses 32 byte key
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
  cipher = OpenSSL::Cipher.new('chacha20-poly1305')
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
  cipher = OpenSSL::Cipher.new('chacha20-poly1305')
  cipher.decrypt
  cipher.key = key
  cipher.iv = nonce
  cipher.auth_tag = tag
  cipher.auth_data = aad
  cipher.padding = 0
  cipher.update(ct_body) << cipher.final
end

pkem = '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a'
pkrm = '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a'
skem = 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600'
skrm = '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb'
shared_secret = '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7'
info = '4f6465206f6e2061204772656369616e2055726e'
key = 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91'
base_nonce = '5c4d98150661b848853b547f'
exporter_secret = 'a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922'

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
ct  = '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28'

puts cipher_seal([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [pt].pack('H*')).unpack1('H*')
puts ct

puts cipher_open([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [ct].pack('H*')).unpack1('H*')
puts pt
