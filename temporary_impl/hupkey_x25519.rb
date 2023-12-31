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

# TODO
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

# TODO
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
  dh = sk_r.derive(pk_e)

  pkrm = serialize_public_key(sk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, KEM_SUITE_ID)
  shared_secret
end

# TODO
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

pkem = '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'
pkrm = '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d'
skem = '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736'
skrm = '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8'
ikme = '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e'
shared_secret = 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc'
info = '4f6465206f6e2061204772656369616e2055726e'
key = '4531685d41d65f03dc48f6b8302c05b0'
base_nonce = '56d890e5accaaf011cff4b7d'
exporter_secret = '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8'

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
ct  = 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a'

puts cipher_seal([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [pt].pack('H*')).unpack1('H*')
puts ct

puts cipher_open([key].pack('H*'), [base_nonce].pack('H*'), [aad].pack('H*'), [ct].pack('H*')).unpack1('H*')
puts pt

# puts ''
# puts '----psk mode----'

# pkem = '04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f'
# pkrm = '040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1'
# skem = '57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f'
# skrm = '438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661'
# psk = '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82'
# psk_id = '456e6e796e20447572696e206172616e204d6f726961'
# shared_secret = '2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b'
# key_schedule_context = '01b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85'
# secret = 'f2f534e55931c62eeb2188c1f53450354a725183937e68c85e68d6b267504d26'
# key = '55d9eb9d26911d4c514a990fa8d57048'
# base_nonce = 'b595dc6b2d7e2ed23af529b1'
# exporter_secret = '895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705'

# pkr = deserialize_public_key(hex_to_str(pkrm))
# encap_result = encap_fixed(pkr, skem)
# puts 'encap:'
# puts encap_result[:shared_secret].unpack1('H*')
# puts ''
# skr = derive_key_pair(hex_to_str(skrm))
# decapped_secret = decap(encap_result[:enc], skr)
# puts 'decap:'
# puts decapped_secret.unpack1('H*')
# puts ''
# puts 'shared secret:'
# puts shared_secret
# puts ''

# key_schedule = key_schedule_s(MODE_PSK, hex_to_str(shared_secret), hex_to_str(info), hex_to_str(psk), hex_to_str(psk_id))

# puts 'key_schedule key, base_nonce, exporter_secret:'
# puts key_schedule[:key].unpack1('H*')
# puts key_schedule[:base_nonce].unpack1('H*')
# puts key_schedule[:exporter_secret].unpack1('H*')
# puts 'key_schedule key, base_nonce, exporter_secret (expected):'
# puts key, base_nonce, exporter_secret
# puts ''

# puts ''
# puts '----auth mode----'

# pkem = '042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454'
# skem = '6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91'
# pkrm = '04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d'
# skrm = 'd929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e'
# pksm = '04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73'
# sksm = '1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9'
# shared_secret = 'd4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f'
# key = '19aa8472b3fdc530392b0e54ca17c0f5'
# base_nonce = 'b390052d26b67a5b8a8fcaa4'
# exporter_secret = 'f152759972660eb0e1db880835abd5de1c39c8e9cd269f6f082ed80e28acb164'

# pkr = deserialize_public_key(hex_to_str(pkrm))
# sks = derive_key_pair(hex_to_str(sksm))

# encap_result = auth_encap_fixed(pkr, sks, skem)

# puts 'encap:'
# puts encap_result[:shared_secret].unpack1('H*')
# puts ''

# skr = derive_key_pair(hex_to_str(skrm))
# pks = deserialize_public_key(hex_to_str(pksm))
# decapped_secret = auth_decap(encap_result[:enc], skr, pks)

# puts 'decap:'
# puts decapped_secret.unpack1('H*')
# puts ''
# puts 'shared secret:'
# puts shared_secret
# puts ''

# key_schedule = key_schedule_s(MODE_AUTH, hex_to_str(shared_secret), hex_to_str(info))

# puts 'key_schedule key, base_nonce, exporter_secret:'
# puts key_schedule[:key].unpack1('H*')
# puts key_schedule[:base_nonce].unpack1('H*')
# puts key_schedule[:exporter_secret].unpack1('H*')
# puts 'key_schedule key, base_nonce, exporter_secret (expected):'
# puts key, base_nonce, exporter_secret
# puts ''

# puts ''
# puts '----authpsk mode----'

# pkem = '046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401'
# skem = '36f771e411cf9cf72f0701ef2b991ce9743645b472e835fe234fb4d6eb2ff5a0'
# pkrm = '04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3'
# skrm = 'bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394'
# pksm = '049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e'
# sksm = 'b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240'
# psk = '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82'
# psk_id = '456e6e796e20447572696e206172616e204d6f726961'
# shared_secret = 'd4c27698391db126f1612d9e91a767f10b9b19aa17e1695549203f0df7d9aebe'
# key = '4d567121d67fae1227d90e11585988fb'
# base_nonce = '67c9d05330ca21e5116ecda6'
# exporter_secret = '3f479020ae186788e4dfd4a42a21d24f3faabb224dd4f91c2b2e5e9524ca27b2'

# pkr = deserialize_public_key(hex_to_str(pkrm))
# sks = derive_key_pair(hex_to_str(sksm))

# encap_result = auth_encap_fixed(pkr, sks, skem)

# puts 'encap:'
# puts encap_result[:shared_secret].unpack1('H*')
# puts ''

# skr = derive_key_pair(hex_to_str(skrm))
# pks = deserialize_public_key(hex_to_str(pksm))
# decapped_secret = auth_decap(encap_result[:enc], skr, pks)

# puts 'decap:'
# puts decapped_secret.unpack1('H*')
# puts ''
# puts 'shared secret:'
# puts shared_secret
# puts ''

# key_schedule = key_schedule_s(MODE_AUTH_PSK, hex_to_str(shared_secret), hex_to_str(info), hex_to_str(psk), hex_to_str(psk_id))

# puts 'key_schedule key, base_nonce, exporter_secret:'
# puts key_schedule[:key].unpack1('H*')
# puts key_schedule[:base_nonce].unpack1('H*')
# puts key_schedule[:exporter_secret].unpack1('H*')
# puts 'key_schedule key, base_nonce, exporter_secret (expected):'
# puts key, base_nonce, exporter_secret
# puts ''