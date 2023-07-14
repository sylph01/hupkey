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
  x.bytes.reduce {|a, b| a * 256 + b}
end

DEFAULT_PSK = ''
DEFAULT_PSK_ID = ''
MODE_BASE     = 0x00
MODE_PSK      = 0x01
MODE_AUTH     = 0x02
MODE_AUTH_PSK = 0x03
MODES = {0 => 'BASE', 1 => 'PSK', 2 =>'AUTH', 3 => 'AUTHPSK'}

# A.3. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
KEM_ID = 32
KDF_ID = 1
AEAD_ID = 1
KEM_SUITE_ID  = 'KEM' + i2osp(KEM_ID, 2)
HPKE_SUITE_ID = 'HPKE' + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)

# KEM constants: see 7.1
N_SECRET = 32
N_ENC = 32
N_PK = 32
N_SK = 32

# KDF constants: see 7.2
N_H = 32

# AEAD constants: see 7.3
N_K = 16
N_N = 12
N_T = 16

def xor(a, b)
  if a.bytesize != b.bytesize
    return false
  end
  c = ""
  for i in 0 .. (a.bytesize - 1)
    c += (a.bytes[i] ^ b.bytes[i]).chr
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
  derive_key_pair(SecureRandom.random_bytes(N_SK))
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

def auth_encap(pk_r, sk_s)
  pkey_e = generate_key_pair()
  dh = pkey_e.derive(pk_r) + sk_s.derive(pk_r)
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
  dh = pkey_e.derive(pk_r) + sk_s.derive(pk_r)
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
  dh = sk_r.derive(pk_e)

  pkrm = serialize_public_key(sk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  shared_secret
end

def auth_decap(enc, sk_r, pk_s)
  pk_e = deserialize_public_key(enc)
  dh = sk_r.derive(pk_e) + sk_r.derive(pk_s)

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
  pkrm: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
  skem: '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
  skrm: '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8',
  shared_secret: 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '4531685d41d65f03dc48f6b8302c05b0',
  base_nonce: '56d890e5accaaf011cff4b7d',
  exporter_secret: '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8',
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '56d890e5accaaf011cff4b7d',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '56d890e5accaaf011cff4b7c',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '56d890e5accaaf011cff4b7f',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '56d890e5accaaf011cff4b82',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_PSK,
  pkrm: '9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366',
  skem: '463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588',
  skrm: 'c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd',
  shared_secret: '727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '15026dba546e3ae05836fc7de5a7bb26',
  base_nonce: '9518635eba129d5ce0914555',
  exporter_secret: '3d76025dbbedc49448ec3f9080a1abab6b06e91c0b11ad23c912f043a0ee7655',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '9518635eba129d5ce0914555',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '9518635eba129d5ce0914554',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22cd62437c8ba'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '9518635eba129d5ce0914557',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '257ca6a08473dc851fde45afd598cc83e326ddd0abe1ef23baa3baa4dd8cde99fce2c1e8ce687b0b47ead1adc9'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '9518635eba129d5ce09145aa',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '55f84b030b7f7197f7d7d552365b6b932df5ec1abacd30241cb4bc4ccea27bd2b518766adfa0fb1b71170e9392'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH,
  pkrm: '1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e',
  skem: 'ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518',
  skrm: 'fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e',
  sksm: 'dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd',
  pksm: '8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b',
  shared_secret: '2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: 'b062cb2c4dd4bca0ad7c7a12bbc341e6',
  base_nonce: 'a1bc314c1942ade7051ffed0',
  exporter_secret: 'ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1',
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: 'a1bc314c1942ade7051ffed0',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: 'a1bc314c1942ade7051ffed1',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'd3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd699f002bc8ed'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: 'a1bc314c1942ade7051ffed2',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '122175cfd5678e04894e4ff8789e85dd381df48dcaf970d52057df2c9acc3b121313a2bfeaa986050f82d93645'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: 'a1bc314c1942ade7051ffe2f',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '55d53d85fe4d9e1e97903101eab0b4865ef20cef28765a47f840ff99625b7d69dee927df1defa66a036fc58ff2'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH_PSK,
  pkrm: '1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976',
  skem: '14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768',
  skrm: 'cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423',
  sksm: 'fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4',
  pksm: '2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e',
  shared_secret: 'f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '1364ead92c47aa7becfa95203037b19a',
  base_nonce: '99d8b5c54669807e9fc70df1',
  exporter_secret: 'f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '99d8b5c54669807e9fc70df1',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '99d8b5c54669807e9fc70df0',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9da127435d9'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '99d8b5c54669807e9fc70df3',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '0c085a365fbfa63409943b00a3127abce6e45991bc653f182a80120868fc507e9e4d5e37bcc384fc8f14153b24'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '99d8b5c54669807e9fc70d0e',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '576d39dd2d4cc77d1a14a51d5c5f9d5e77586c3d8d2ab33bdec6379e28ce5c502f0b1cbd09047cf9eb9269bb52'
    }
  },
  max_seq: 256
})