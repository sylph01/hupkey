require_relative 'hpke'

def test(vec)
  dhkem = DHKEM::EC::P_256.new(:sha256)
  hpke = HPKE.new(dhkem, :sha256, :aes_128_gcm)

  puts "mode: #{vec[:mode]}"
  puts ''

  ikme = vec[:skem]
  pkr = dhkem.deserialize_public_key([vec[:pkrm]].pack('H*'))
  skr = dhkem.create_key_pair_from_secret([vec[:skrm]].pack('H*'))
  sks = dhkem.create_key_pair_from_secret([vec[:sksm]].pack('H*'))

  encap_result = dhkem.encap_fixed(pkr, ikme)

  puts "shared_secret(got): #{encap_result[:shared_secret].unpack1('H*')}"
  puts "shared_secret(exp): #{vec[:shared_secret]}"

  decapped_secret = dhkem.decap(encap_result[:enc], skr)
  puts "decapped_secret: #{decapped_secret.unpack1('H*')}"

  info_ = [vec[:info]].pack('H*')
  ss = hpke.setup_base_s_fixed(pkr, info_, ikme)
  ksr = hpke.setup_base_r(ss[:enc], skr, info_)

  kss = ss[:key_schedule_s]

  puts 'key, base_nonce, exporter_secret (got):'
  puts kss.key.unpack1('H*'), kss.base_nonce.unpack1('H*'), kss.exporter_secret.unpack1('H*')
  puts ksr.key.unpack1('H*'), ksr.base_nonce.unpack1('H*'), ksr.exporter_secret.unpack1('H*')
  puts 'key, base_nonce, exporter_secret (expected):'
  puts vec[:key], vec[:base_nonce], vec[:exporter_secret]

  for iter in 0..vec[:max_seq] do
    if vec[:enc_vecs][iter]
      enc_vec = vec[:enc_vecs][iter]
      puts "seq: #{iter}"
      puts "seq in key_schedule_s: #{kss.sequence_number}"
      puts "computed nonce: #{kss.compute_nonce(iter).unpack1('H*')}"
      puts "expected nonce: #{enc_vec[:nonce]}"

      ct = kss.seal([enc_vec[:aad]].pack('H*'), [enc_vec[:pt]].pack('H*'))
      puts "ct(got): #{ct.unpack1('H*')}"
      puts "ct(exp): #{enc_vec[:ct]}"

      pt = ksr.open([enc_vec[:aad]].pack('H*'), [enc_vec[:ct]].pack('H*'))
      puts "pt(got): #{pt.unpack1('H*')}"
      puts "pt(exp): #{enc_vec[:pt]}"

      puts ''
    else
      kss.increment_seq
      ksr.increment_seq
    end
  end
end

test({
  mode: 0x01,
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