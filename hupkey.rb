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
MODES = {0 => 'BASE', 1 => 'PSK', 2 =>'AUTH', 3 => 'AUTHPSK'}

# A.3. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
KEM_ID = 16
KDF_ID = 1
AEAD_ID = 1
KEM_SUITE_ID  = 'KEM' + i2osp(KEM_ID, 2)
HPKE_SUITE_ID = 'HPKE' + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)

# KEM constants: see 7.1
N_SECRET = 32
N_ENC = 65
N_PK = 65
N_SK = 32

# KDF constants: see 7.2
N_H = 32

# AEAD constants: see 7.3
N_K = 16
N_N = 12
N_T = 16

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

  labeled_expand(eae_prk, 'shared_secret', kem_context, N_SECRET, suite_id)
end

def generate_key_pair
  # OpenSSL::PKey::EC.generate('prime256v1')
  derive_key_pair(SecureRandom.random_bytes(N_SK))
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
    # TODO: catch openerror then send out own openerror
    increment_seq
    pt
  end

  private

  def cipher_open(key, nonce, aad, ct)
    ct_body = ct[0, ct.length - N_T]
    tag = ct[-N_T, N_T]
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

  key = labeled_expand(secret, 'key', key_schedule_context, N_K, HPKE_SUITE_ID)
  base_nonce = labeled_expand(secret, 'base_nonce', key_schedule_context, N_N, HPKE_SUITE_ID)
  exporter_secret = labeled_expand(secret, 'exp', key_schedule_context, N_H, HPKE_SUITE_ID)

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
  puts "mode: #{vec[:mode]} (#{MODES[vec[:mode]]})"
  puts ''

  puts 'encap'
  pkr = deserialize_public_key([vec[:pkrm]].pack('H*'))
  if [MODE_BASE, MODE_PSK].include?(vec[:mode])
    encap_result = encap_fixed(pkr, vec[:skem])
  else
    sks = derive_key_pair([vec[:sksm]].pack('H*'))
    encap_result = auth_encap_fixed(pkr, sks, vec[:skem])
  end
  puts "shared_secret(got): #{encap_result[:shared_secret].unpack1('H*')}"
  puts "shared_secret(exp): #{vec[:shared_secret]}"
  puts ''

  puts 'decap'
  skr = derive_key_pair([vec[:skrm]].pack('H*'))
  if [MODE_BASE, MODE_PSK].include?(vec[:mode])
    decapped_secret = decap(encap_result[:enc], skr)
  else
    pks = deserialize_public_key([vec[:pksm]].pack('H*'))
    decapped_secret = auth_decap(encap_result[:enc], skr, pks)
  end
  puts "decapped_secret: #{decapped_secret.unpack1('H*')}"
  puts ''

  puts 'key schedule'
  key_schedule_s_inst = key_schedule_s(vec[:mode], hex_to_str(vec[:shared_secret]), hex_to_str(vec[:info]), hex_to_str(vec[:psk]), hex_to_str(vec[:psk_id]))
  key_schedule_r_inst = key_schedule_r(vec[:mode], hex_to_str(vec[:shared_secret]), hex_to_str(vec[:info]), hex_to_str(vec[:psk]), hex_to_str(vec[:psk_id]))
  puts 'key, base_nonce, exporter_secret (got):'
  puts key_schedule_s_inst.key.unpack1('H*'), key_schedule_s_inst.base_nonce.unpack1('H*'), key_schedule_s_inst.exporter_secret.unpack1('H*')
  puts 'key, base_nonce, exporter_secret (expected):'
  puts vec[:key], vec[:base_nonce], vec[:exporter_secret]
  puts ''

  for iter in 0..vec[:max_seq] do
    if vec[:enc_vecs][iter]
      enc_vec = vec[:enc_vecs][iter]
      puts "seq: #{iter}"
      puts "seq in key_schedule_s: #{key_schedule_s_inst.sequence_number}"
      puts "computed nonce: #{key_schedule_s_inst.compute_nonce(iter).unpack1('H*')}"
      puts "expected nonce: #{enc_vec[:nonce]}"

      ct = key_schedule_s_inst.seal([enc_vec[:aad]].pack('H*'), [enc_vec[:pt]].pack('H*'))
      puts "ct(got): #{ct.unpack1('H*')}"
      puts "ct(exp): #{enc_vec[:ct]}"

      pt = key_schedule_r_inst.open([enc_vec[:aad]].pack('H*'), [enc_vec[:ct]].pack('H*'))
      puts "pt(got): #{pt.unpack1('H*')}"
      puts "pt(exp): #{enc_vec[:pt]}"

      puts ''
    else
      key_schedule_s_inst.increment_seq
      key_schedule_r_inst.increment_seq
    end
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
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '4e0bc5018beba4bf004cca59',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '4e0bc5018beba4bf004cca58',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '4e0bc5018beba4bf004cca5b',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '4e0bc5018beba4bf004ccaa6',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_PSK,
  pkrm: '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1',
  skem: '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f',
  skrm: '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661',
  shared_secret: '2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '55d9eb9d26911d4c514a990fa8d57048',
  base_nonce: 'b595dc6b2d7e2ed23af529b1',
  exporter_secret: '895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      aad: '436f756e742d30',
      nonce: 'b595dc6b2d7e2ed23af529b1',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: 'b595dc6b2d7e2ed23af529b0',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a1073a7102c27'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: 'b595dc6b2d7e2ed23af529b3',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0c7781465b2'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: 'b595dc6b2d7e2ed23af5294e',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'cdc541253111ed7a424eea5134dc14fc5e8293ab3b537668b8656789628e45894e5bb873c968e3b7cdcbb654a4'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH,
  pkrm: '04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d',
  skem: '6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91',
  skrm: 'd929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e',
  pksm: '04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73',
  sksm: '1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9',
  shared_secret: 'd4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '19aa8472b3fdc530392b0e54ca17c0f5',
  base_nonce: 'b390052d26b67a5b8a8fcaa4',
  exporter_secret: 'f152759972660eb0e1db880835abd5de1c39c8e9cd269f6f082ed80e28acb164',
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      aad: '436f756e742d30',
      nonce: 'b390052d26b67a5b8a8fcaa4',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: 'b390052d26b67a5b8a8fcaa5',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e3966aa1250'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: 'b390052d26b67a5b8a8fcaa6',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '8dc805680e3271a801790833ed74473710157645584f06d1b53ad439078d880b23e25256663178271c80ee8b7c'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: 'b390052d26b67a5b8a8fca5b',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '4a319462eaedee37248b4d985f64f4f863d31913fe9e30b6e13136053b69fe5d70853c84c60a84bb5495d5a678'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH_PSK,
  pkrm: '04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3',
  skem: '36f771e411cf9cf72f0701ef2b991ce9743645b472e835fe234fb4d6eb2ff5a0',
  skrm: 'bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394',
  pksm: '049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e',
  sksm: 'b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240',
  shared_secret: 'd4c27698391db126f1612d9e91a767f10b9b19aa17e1695549203f0df7d9aebe',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '4d567121d67fae1227d90e11585988fb',
  base_nonce: '67c9d05330ca21e5116ecda6',
  exporter_secret: '3f479020ae186788e4dfd4a42a21d24f3faabb224dd4f91c2b2e5e9524ca27b2',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      aad: '436f756e742d30',
      nonce: '67c9d05330ca21e5116ecda6',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '67c9d05330ca21e5116ecda7',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579c10fc09736'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '67c9d05330ca21e5116ecda4',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '3b5a2be002e7b29927f06442947e1cf709b9f8508b03823127387223d712703471c266efc355f1bc2036f3027c'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '67c9d05330ca21e5116ecd59',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '6de25ceadeaec572fbaa25eda2558b73c383fe55106abaec24d518ef6724a7ce698f83ecdc53e640fe214d2f42'
    }
  },
  max_seq: 256
})