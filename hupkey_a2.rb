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
AEAD_ID = 3
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
N_K = 32
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
    cipher = OpenSSL::Cipher.new('chacha20-poly1305')
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
    cipher = OpenSSL::Cipher.new('chacha20-poly1305')
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
  pkrm: '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
  skem: 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600',
  skrm: '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb',
  shared_secret: '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91',
  base_nonce: '5c4d98150661b848853b547f',
  exporter_secret: 'a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922',
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '5c4d98150661b848853b547f',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '5c4d98150661b848853b547e',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '5c4d98150661b848853b547d',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '5c4d98150661b848853b5480',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_PSK,
  pkrm: '13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062',
  skem: '0c35fdf49df7aa01cd330049332c40411ebba36e0c718ebc3edf5845795f6321',
  skrm: '77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879',
  shared_secret: '4be079c5e77779d0215b3f689595d59e3e9b0455d55662d1f3666ec606e50ea7',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '600d2fdb0313a7e5c86a9ce9221cd95bed069862421744cfb4ab9d7203a9c019',
  base_nonce: '112e0465562045b7368653e7',
  exporter_secret: '73b506dc8b6b4269027f80b0362def5cbb57ee50eed0c2873dac9181f453c5ac',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: '112e0465562045b7368653e7',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: '112e0465562045b7368653e6',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '5c3cabae2f0b3e124d8d864c116fd8f20f3f56fda988c3573b40b09997fd6c769e77c8eda6cda4f947f5b704a8'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: '112e0465562045b7368653e5',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '14958900b44bdae9cbe5a528bf933c5c990dbb8e282e6e495adf8205d19da9eb270e3a6f1e0613ab7e757962a4'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: '112e0465562045b736865318',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '2414d0788e4bc39a59a26d7bd5d78e111c317d44c37bd5a4c2a1235f2ddc2085c487d406490e75210c958724a7'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH,
  pkrm: '1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44',
  skem: 'c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13',
  skrm: '3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82',
  sksm: '2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05',
  pksm: 'f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b',
  shared_secret: 'd2d67828c8bc9fa661cf15a31b3ebf1febe0cafef7abfaaca580aaf6d471e3eb',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: 'b071fd1136680600eb447a845a967d35e9db20749cdf9ce098bcc4deef4b1356',
  base_nonce: 'd20577dff16d7cea2c4bf780',
  exporter_secret: 'be2d93b82071318cdb88510037cf504344151f2f9b9da8ab48974d40a2251dd7',
  psk: '',
  psk_id: '',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: 'd20577dff16d7cea2c4bf780',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: 'ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: 'd20577dff16d7cea2c4bf781',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '3265c7807ffff7fdace21659a2c6ccffee52a26d270c76468ed74202a65478bfaedfff9c2b7634e24f10b71016'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: 'd20577dff16d7cea2c4bf782',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '3aadee86ad2a05081ea860033a9d09dbccb4acac2ded0891da40f51d4df19925f7a767b076a5cbc9355c8fd35e'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: 'd20577dff16d7cea2c4bf77f',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '652e597ba20f3d9241cda61f33937298b1169e6adf72974bbe454297502eb4be132e1c5064702fc165c2ddbde8'
    }
  },
  max_seq: 256
})

test({
  mode: MODE_AUTH_PSK,
  pkrm: 'a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851',
  skem: '5e6dd73e82b856339572b7245d3cbb073a7561c0bee52873490e305cbb710410',
  skrm: '7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c',
  sksm: '90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418',
  pksm: '3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45',
  shared_secret: '86a6c0ed17714f11d2951747e660857a5fd7616c933ef03207808b7a7123fe67',
  info: '4f6465206f6e2061204772656369616e2055726e',
  key: '49c7e6d7d2d257aded2a746fe6a9bf12d4de8007c4862b1fdffe8c35fb65054c',
  base_nonce: 'abac79931e8c1bcb8a23960a',
  exporter_secret: '7c6cc1bb98993cd93e2599322247a58fd41fdecd3db895fb4c5fd8d6bbe606b5',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  enc_vecs: {
    0 => {
      seq: 0,
      aad: '436f756e742d30',
      nonce: 'abac79931e8c1bcb8a23960a',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597'
    },
    1 => {
      aad: '436f756e742d31',
      nonce: 'abac79931e8c1bcb8a23960b',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '59460bacdbe7a920ef2806a74937d5a691d6d5062d7daafcad7db7e4d8c649adffe575c1889c5c2e3a49af8e3e'
    },
    2 => {
      aad: '436f756e742d32',
      nonce: 'abac79931e8c1bcb8a239608',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '5688ff6a03ba26ae936044a5c800f286fb5d1eccdd2a0f268f6ff9773b51169318d1a1466bb36263415071db00'
    },
    255 => {
      aad: '436f756e742d323535',
      nonce: 'abac79931e8c1bcb8a2396f5',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      ct: '4d4c462f7b9b637eaf1f4e15e325b7bc629c0af6e3073422c86064cc3c98cff87300f054fd56dd57dc34358beb'
    }
  },
  max_seq: 256
})