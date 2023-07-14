require_relative 'hpke'

MODE_BASE     = 0x00
MODE_PSK      = 0x01
MODE_AUTH     = 0x02
MODE_AUTH_PSK = 0x03

def test(vec)
  hpke = HPKE.new(vec[:kem_curve], vec[:kem_hash], vec[:kdf_hash], vec[:aead_cipher])

  puts "hpke: DHKEM(#{vec[:kem_curve]}, #{vec[:kem_hash]}), #{vec[:kdf_hash]}, #{vec[:aead_cipher]}"
  p hpke
  puts "mode: #{vec[:mode]}"
  puts ''

  ikme = vec[:skem]
  pkr = hpke.kem.deserialize_public_key([vec[:pkrm]].pack('H*'))
  skr = hpke.kem.create_key_pair_from_secret([vec[:skrm]].pack('H*'))
  sks = hpke.kem.create_key_pair_from_secret([vec[:sksm]].pack('H*'))
  info_ = [vec[:info]].pack('H*')

  case vec[:mode]
  when MODE_BASE
    ss = hpke.setup_base_s_fixed(pkr, info_, ikme)
    ksr = hpke.setup_base_r(ss[:enc], skr, info_)
    kss = ss[:key_schedule_s]
  when MODE_PSK
    psk = [vec[:psk]].pack('H*')
    psk_id = [vec[:psk_id]].pack('H*')
    ss = hpke.setup_psk_s_fixed(pkr, info_, psk, psk_id, ikme)
    ksr = hpke.setup_psk_r(ss[:enc], skr, info_, psk, psk_id)
    kss = ss[:key_schedule_s]
  when MODE_AUTH
    pks = hpke.kem.deserialize_public_key([vec[:pksm]].pack('H*'))
    ss = hpke.setup_auth_s_fixed(pkr, info_, sks, ikme)
    ksr = hpke.setup_auth_r(ss[:enc], skr, info_, pks)
    kss = ss[:key_schedule_s]
  when MODE_AUTH_PSK
    psk = [vec[:psk]].pack('H*')
    psk_id = [vec[:psk_id]].pack('H*')
    pks = hpke.kem.deserialize_public_key([vec[:pksm]].pack('H*'))
    ss = hpke.setup_auth_psk_s_fixed(pkr, info_, psk, psk_id, sks, ikme)
    ksr = hpke.setup_auth_psk_r(ss[:enc], skr, info_, psk, psk_id, pks)
    kss = ss[:key_schedule_s]
  end

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
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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

test({
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :aes_128_gcm,
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