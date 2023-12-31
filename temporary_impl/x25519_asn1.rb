require 'openssl'
require 'securerandom'
require 'base64'

# https://datatracker.ietf.org/doc/html/rfc7748
# https://datatracker.ietf.org/doc/html/rfc8410
# also https://datatracker.ietf.org/doc/html/rfc7468
asn1_seq = OpenSSL::ASN1.Sequence([
  OpenSSL::ASN1.Integer(0),
  OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.ObjectId('1.3.101.110')
  ]),
  OpenSSL::ASN1.OctetString("\x04\x20" + SecureRandom.random_bytes(32))
])

puts Base64.encode64(asn1_seq.to_der).delete("\n")
pkey = OpenSSL::PKey.read(asn1_seq.to_der)

puts Base64.encode64(pkey.private_to_der).delete("\n")

asn1_seq_pub = OpenSSL::ASN1.Sequence([
  OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.ObjectId('1.3.101.110')
  ]),
  OpenSSL::ASN1.BitString(pkey.public_to_der[-32, 32])
])

puts pkey.public_to_der[-32, 32].unpack1('H*')
pubkey = OpenSSL::PKey.read(asn1_seq_pub.to_der)
puts pubkey.public_to_der[-32, 32].unpack1('H*')

asn1_seq_448 = OpenSSL::ASN1.Sequence([
  OpenSSL::ASN1.Integer(0),
  OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.ObjectId('1.3.101.111')
  ]),
  OpenSSL::ASN1.OctetString("\x04\x38" + SecureRandom.random_bytes(56))
])

puts Base64.encode64(asn1_seq_448.to_der).delete("\n")
pkey448 = OpenSSL::PKey.read(asn1_seq_448.to_der)

puts Base64.encode64(pkey448.private_to_der).delete("\n")

asn1_seq_448_pub = OpenSSL::ASN1.Sequence([
  OpenSSL::ASN1.Sequence([
    OpenSSL::ASN1.ObjectId('1.3.101.111')
  ]),
  OpenSSL::ASN1.BitString(pkey448.public_to_der[-56, 56])
])

puts pkey448.public_to_der[-56, 56].unpack1('H*')
pubkey448 = OpenSSL::PKey.read(asn1_seq_448_pub.to_der)
puts pubkey448.public_to_der[-56, 56].unpack1('H*')