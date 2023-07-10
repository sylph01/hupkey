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

  n_secret = 32 # P-256 uses 32, based on section 4.1
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
  dh = pkey_e.dh_compute_key(pk_r)
  enc = serialize_public_key(pkey_e)

  pkrm = serialize_public_key(pk_r)
  kem_context = enc + pkrm

  shared_secret = extract_and_expand(dh, kem_context, 'KEM' + i2osp(16, 2))
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

  shared_secret = extract_and_expand(dh, kem_context, 'KEM' + i2osp(16, 2))
  {
    shared_secret: shared_secret.unpack1('H*'),
    enc: enc
  }
end

pkem = '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'
pkrm = '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'
skem = '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'
skrm = 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'
ikme = '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e'

pkr = deserialize_public_key(hex_to_str(pkrm))

encap_result = encap_fixed(pkr, skem)

puts encap_result[:shared_secret]
puts encap_result[:enc].unpack1('H*')