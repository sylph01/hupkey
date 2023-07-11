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

class Context
  attr_reader :key, :base_nonce, :sequence_number, :exporter_secret

  N_N = 12

  def initialize(initializer_hash)
    @key = initializer_hash[:key]
    @base_nonce = initializer_hash[:base_nonce]
    @sequence_number = initializer_hash[:sequence_number]
    @exporter_secret = initializer_hash[:exporter_secret]
  end

  def compute_nonce(seq)
    seq_bytes = i2osp(seq, N_N)
    xor(@base_nonce, seq_bytes)
  end

  private

  def increment_seq
    raise Exception.new('MessageLimitReachedError') if @sequence_number >= (1 << (8 * N_N)) - 1

    @sequence_number += 1
  end
end

class ContextS < Context
  def seal(aad, pt)
    ct = cipher_seal(@key, compute_nonce(@sequence_number), aad, pt)
    increment_seq
    ct
  end

  private

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
end

class ContextR < Context
  def open(aad, ct)
    pt = cipher_open(@key, compute_nonce(@sequence_number), aad, ct)
    # catch openerror then send out own openerror
    increment_seq
    pt
  end

  private

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
    key: key,
    base_nonce: base_nonce,
    sequence_number: 0,
    exporter_secret: exporter_secret
  }
end

def key_schedule_s(mode, shared_secret, info, psk = '', psk_id = '')
  ks = key_schedule(mode, shared_secret, info, psk, psk_id)
  ContextS.new(ks)
end

def key_schedule_r(mode, shared_secret, info, psk = '', psk_id = '')
  ks = key_schedule(mode, shared_secret, info, psk, psk_id)
  ContextR.new(ks)
end

def test(vec)
  puts "mode: #{vec[:mode]}"
  puts ''

  puts 'encap'
  pkr = deserialize_public_key([vec[:pkrm]].pack('H*'))
  encap_result = encap_fixed(pkr, vec[:skem])
  puts "shared_secret(got): #{encap_result[:shared_secret].unpack1('H*')}"
  puts "shared_secret(exp): #{vec[:shared_secret]}"
  puts ''

  puts 'decap'
  skr = derive_key_pair([vec[:skrm]].pack('H*'))
  decapped_secret = decap(encap_result[:enc], skr)
  puts "decapped_secret: #{decapped_secret.unpack1('H*')}"
  puts ''

  puts 'key schedule'
  key_schedule_s_inst = key_schedule_s(vec[:mode], hex_to_str(vec[:shared_secret]), hex_to_str(vec[:info]))
  key_schedule_r_inst = key_schedule_r(vec[:mode], hex_to_str(vec[:shared_secret]), hex_to_str(vec[:info]))
  puts 'key, base_nonce, exporter_secret (got):'
  puts key_schedule_s_inst.key.unpack1('H*'), key_schedule_s_inst.base_nonce.unpack1('H*'), key_schedule_s_inst.exporter_secret.unpack1('H*')
  puts 'key, base_nonce, exporter_secret (expected):'
  puts vec[:key], vec[:base_nonce], vec[:exporter_secret]
  puts ''

  vec[:enc_vecs].each do |enc_vec|
    puts "seq: #{enc_vec[:seq]}"
    puts "computed nonce: #{key_schedule_s_inst.compute_nonce(enc_vec[:seq]).unpack1('H*')}"
    puts "expected nonce: #{enc_vec[:nonce]}"

    ct = key_schedule_s_inst.seal([enc_vec[:aad]].pack('H*'), [enc_vec[:pt]].pack('H*'))
    puts "ct(got): #{ct.unpack1('H*')}"
    puts "ct(exp): #{enc_vec[:ct]}"

    pt = key_schedule_r_inst.open([enc_vec[:aad]].pack('H*'), [enc_vec[:ct]].pack('H*'))
    puts "pt(got): #{pt.unpack1('H*')}"
    puts "pt(exp): #{enc_vec[:pt]}"

    puts ''
  end
end

test({
  mode: MODE_BASE,
  pkrm: '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
  skem: '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
  skrm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
  shared_secret: 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '868c066ef58aae6dc589b6cfdd18f97e',
  base_nonce: '4e0bc5018beba4bf004cca59',
  exporter_secret: '14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f',
  enc_vecs: [
    {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '4e0bc5018beba4bf004cca59',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
    },
    {
      seq: 1,
      aad: '436f756e742d31',
      nonce: '4e0bc5018beba4bf004cca58',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'
    },
    {
      seq: 2,
      aad: '436f756e742d32',
      nonce: '4e0bc5018beba4bf004cca5b',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'
    },
  ]
})
