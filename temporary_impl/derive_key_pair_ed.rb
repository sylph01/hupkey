require 'openssl'
require 'securerandom'

# ---- util ----

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

def hex_to_str(hex)
  hex = hex.slice(2..-1) if hex.start_with?('0x')
  [hex].pack('H*')
end

def and(a, b)
  if a.length != b.length
    return false
  end
  c = ""
  for i in 0 .. (a.length - 1)
    c += (a[i].ord & b[i].ord).chr
  end
  c
end

# ---- hash ----
KEM_ID = 32 # X25519, HKDF-SHA256
KEM_SUITE_ID  = 'KEM' + i2osp(KEM_ID, 2)

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

  n_secret = 32 # P-256 uses 32, based on section 4.1
  labeled_expand(eae_prk, 'shared_secret', kem_context, n_secret, suite_id)
end

P_256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P_384_ORDER = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
P_521_ORDER = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

N_SK = 32

def derive_key_pair(ikm)
  dkp_prk = labeled_extract('', 'dkp_prk', ikm, KEM_SUITE_ID)
  sk = labeled_expand(dkp_prk, 'sk', '', N_SK, KEM_SUITE_ID)
  sk_obj = create_key_pair_from_secret(sk)
  puts sk.unpack1('H*')
  sk_obj
end

def create_key_pair_from_secret(secret)
  asn1_seq = OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.Integer(0),
    OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.ObjectId('1.3.101.110')
    ]),
    OpenSSL::ASN1.OctetString("\x04\x20" + secret)
  ])

  OpenSSL::PKey.read(asn1_seq.to_der)
end

def serialize_public_key(pk)
  pk.public_to_der[-32, 32]
end

ikm = '7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234' # ikme
sk_obj = derive_key_pair([ikm].pack('H*'))
puts serialize_public_key(sk_obj).unpack1('H*')

puts "skem: 52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
puts "pkem: 37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"