require 'openssl'
require 'securerandom'
require_relative 'hkdf'
require_relative 'util'

class DHKEM
  include Util

  attr_reader :kem_id

  def initialize(hash_name)
    @hkdf = HKDF.new(hash_name)
  end

  def encap(pk_r)
    pkey_e = generate_key_pair()
    dh = pkey_e.derive(pk_r)
    enc = serialize_public_key(pkey_e)

    pkrm = serialize_public_key(pk_r)
    kem_context = enc + pkrm

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
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

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
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

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
    shared_secret
  end

  def auth_decap(enc, sk_r, pk_s)
    pk_e = deserialize_public_key(enc)
    dh = sk_r.derive(pk_e) + sk_r.derive(pk_s)

    pkrm = serialize_public_key(sk_r)
    pksm = serialize_public_key(pk_s)
    kem_context = enc + pkrm + pksm

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
    shared_secret
  end

  def encap_fixed(pk_r, ikm_e)
    pkey_e = create_key_pair_from_secret(ikm_e)
    dh = pkey_e.derive(pk_r)
    enc = serialize_public_key(pkey_e)

    pkrm = serialize_public_key(pk_r)
    kem_context = enc + pkrm

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
    {
      shared_secret: shared_secret,
      enc: enc
    }
  end

  def auth_encap_fixed(pk_r, sk_s, ikm_e)
    pkey_e = create_key_pair_from_secret(ikm_e)
    dh = pkey_e.derive(pk_r) + sk_s.derive(pk_r)
    enc = serialize_public_key(pkey_e)

    pkrm = serialize_public_key(pk_r)
    pksm = serialize_public_key(sk_s)
    kem_context = enc + pkrm + pksm

    shared_secret = extract_and_expand(dh, kem_context, kem_suite_id)
    {
      shared_secret: shared_secret,
      enc: enc
    }
  end

  def generate_key_pair
    derive_key_pair(SecureRandom.random_bytes(n_sk))
  end

  # ---- functions for Edwards curves (X25519, X448) ----
  def derive_key_pair(ikm)
    dkp_prk = @hkdf.labeled_extract('', 'dkp_prk', ikm, kem_suite_id)
    sk = @hkdf.labeled_expand(dkp_prk, 'sk', '', n_sk, kem_suite_id)

    create_key_pair_from_secret(sk)
  end

  def create_key_pair_from_secret(secret)
    asn1_seq = OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.Integer(0),
      OpenSSL::ASN1.Sequence([
        OpenSSL::ASN1.ObjectId(asn1_oid)
      ]),
      OpenSSL::ASN1.OctetString("\x04\x20" + secret) # TODO: different value for X448?
    ])

    OpenSSL::PKey.read(asn1_seq.to_der)
  end

  def serialize_public_key(pk)
    pk.public_to_der[-n_pk, n_pk]
  end

  def deserialize_public_key(serialized_pk)
    asn1_seq_pub = OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.Sequence([
        OpenSSL::ASN1.ObjectId(asn1_oid)
      ]),
      OpenSSL::ASN1.BitString(serialized_pk)
    ])

    OpenSSL::PKey.read(asn1_seq_pub.to_der)
  end

  private
  
  def kem_suite_id
    'KEM' + i2osp(kem_id, 2)
  end

  def extract_and_expand(dh, kem_context, suite_id)
    eae_prk = @hkdf.labeled_extract('', 'eae_prk', dh, suite_id)

    @hkdf.labeled_expand(eae_prk, 'shared_secret', kem_context, n_secret, suite_id)
  end
end

class DHKEM::EC < DHKEM
  def derive_key_pair(ikm)
    dkp_prk = @hkdf.labeled_extract('', 'dkp_prk', ikm, kem_suite_id)
    sk = 0
    counter = 0
    while sk == 0 || sk >= order do
      raise Exception.new('DeriveKeyPairError') if counter > 255

      bytes = @hkdf.labeled_expand(dkp_prk, 'candidate', i2osp(counter, 1), n_sk, kem_suite_id)
      bytes[0] = (bytes[0].ord & bitmask).chr
      sk = os2ip(bytes)
      counter += 1
    end

    create_key_pair_from_secret(bytes)
  end

  def create_key_pair_from_secret(secret)
    asn1_seq = OpenSSL::ASN1.Sequence([
      OpenSSL::ASN1.Integer(1),
      OpenSSL::ASN1.OctetString(secret),
      OpenSSL::ASN1.ObjectId(curve_name, 0, :EXPLICIT)
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
        OpenSSL::ASN1.ObjectId(curve_name)
      ]),
      OpenSSL::ASN1.BitString(serialized_pk)
    ])

    OpenSSL::PKey.read(asn1_seq.to_der)
  end
end

class DHKEM::EC::P_256 < DHKEM::EC
  def kem_id
    0x0010
  end

  def n_secret
    32
  end

  def n_enc
    65
  end

  def n_pk
    65
  end

  def n_sk
    32
  end

  def order
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  end

  def curve_name
    'prime256v1'
  end

  def bitmask
    0xff
  end
end

class DHKEM::EC::P_384 < DHKEM::EC
  def kem_id
    0x0011
  end

  def n_secret
    48
  end

  def n_enc
    97
  end

  def n_pk
    97
  end

  def n_sk
    48
  end

  def order
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
  end

  def curve_name
    'secp384r1'
  end

  def bitmask
    0xff
  end
end

class DHKEM::EC::P_521 < DHKEM::EC
  def kem_id
    0x0012
  end

  def n_secret
    64
  end

  def n_enc
    133
  end

  def n_pk
    133
  end

  def n_sk
    66
  end

  def order
    0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
  end

  def curve_name
    'secp521r1'
  end

  def bitmask
    0x01
  end
end

class DHKEM::X25519 < DHKEM
  def kem_id
    0x0020
  end

  def n_secret
    32
  end

  def n_enc
    32
  end

  def n_pk
    32
  end

  def n_sk
    32
  end

  def asn1_oid
    '1.3.101.110'
  end
end

class DHKEM::X448 < DHKEM
  def kem_id
    0x0021
  end

  def n_secret
    64
  end

  def n_enc
    56
  end

  def n_pk
    56
  end

  def n_sk
    56
  end

  def asn1_oid
    '1.3.101.111'
  end
end

p256 = DHKEM::EC::P_256.new(:sha256)
# ikm = '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e' # ikme
# sk_obj, pk_obj = p256.derive_key_pair([ikm].pack('H*'))
# puts sk_obj.public_key.to_bn.to_s(16).downcase

# pkrm = '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'
# skem = '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'
# shared_secret = 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8'
# skrm = 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'

# puts 'encap'
# pkr = p256.deserialize_public_key([pkrm].pack('H*'))
# encap_result = p256.encap_fixed(pkr, skem)
# puts "shared_secret(got): #{encap_result[:shared_secret].unpack1('H*')}"
# puts "shared_secret(exp): #{shared_secret}"
# puts ''

# puts 'decap'
# skr = p256.create_key_pair_from_secret([skrm].pack('H*'))
# decapped_secret = p256.decap(encap_result[:enc], skr)
# puts "decapped_secret: #{decapped_secret.unpack1('H*')}"
# puts ''

# x25519 = DHKEM::X25519.new(:sha256)
# ikm = '7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234' # ikme
# sk_obj = x25519.derive_key_pair([ikm].pack('H*'))
# puts x25519.serialize_public_key(sk_obj).unpack1('H*')