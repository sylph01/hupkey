test({
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha512,
  aead_cipher: :aes_128_gcm,
  mode: MODE_BASE,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c',
  pkrm: '04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd',
  skrm: '3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38',
  psk: '',
  psk_id: '',
  shared_secret: '02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd',
  key: '090ca96e5f8aa02b69fac360da50ddf9',
  base_nonce: '9c995e621bf9a20c5ca45546',
  exporter_secret: '4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7bca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba610480ac03efa8',
  enc_vecs: {
    0 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d30',
      nonce: '9c995e621bf9a20c5ca45546',
      ct: 'd3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba'
    },
    1 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d31',
      nonce: '9c995e621bf9a20c5ca45547',
      ct: 'd14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d'
    },
    2 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d32',
      nonce: '9c995e621bf9a20c5ca45544',
      ct: '9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800'
    },
    255 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d323535',
      nonce: '9c995e621bf9a20c5ca455b9',
      ct: 'be5da649469efbad0fb950366a82a73fefeda5f652ec7d3731fac6c4ffa21a7004d2ab8a04e13621bd3629547d'
    }
  },
  max_seq: 256
})

test({
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha512,
  aead_cipher: :aes_128_gcm,
  mode: MODE_PSK,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: 'a5901ff7d6931959c2755382ea40a4869b1dec3694ed3b009dda2d77dd488f18',
  pkrm: '043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd84d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873',
  skrm: 'bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  shared_secret: '2912aacc6eaebd71ff715ea50f6ef3a6637856b2a4c58ea61e0c3fc159e3bc16',
  key: '0b910ba8d9cfa17e5f50c211cb32839a',
  base_nonce: '0c29e714eb52de5b7415a1b7',
  exporter_secret: '50c0a182b6f94b4c0bd955c4aa20df01f282cc12c43065a0812fe4d4352790171ed2b2c4756ad7f5a730ba336c8f1edd0089d8331192058c385bae39c7cc8b57',
  enc_vecs: {
    0 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d30',
      nonce: '0c29e714eb52de5b7415a1b7',
      ct: '57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e8306da41d4cc'
    },
    1 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d31',
      nonce: '0c29e714eb52de5b7415a1b6',
      ct: '159d6b4c24bacaf2f5049b7863536d8f3ffede76302dace42080820fa51925d4e1c72a64f87b14291a3057e00a'
    },
    2 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d32',
      nonce: '0c29e714eb52de5b7415a1b5',
      ct: 'bd24140859c99bf0055075e9c460032581dd1726d52cf980d308e9b20083ca62e700b17892bcf7fa82bac751d0'
    },
    255 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d323535',
      nonce: '0c29e714eb52de5b7415a148',
      ct: '377a98a3c34bf716581b05a6b3fdc257f245856384d5f2241c8840571c52f5c85c21138a4a81655edab8fe227d'
    }
  },
  max_seq: 256
})

test({
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha512,
  aead_cipher: :aes_128_gcm,
  mode: MODE_AUTH,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '93cddd5288e7ef4884c8fe321d075df01501b993ff49ffab8184116f39b3c655',
  pkrm: '04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276',
  skrm: '1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236',
  pksm: '0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529',
  sksm: '02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579',
  psk: '',
  psk_id: '',
  shared_secret: '1ed49f6d7ada333d171cd63861a1cb700a1ec4236755a9cd5f9f8f67a2f8e7b3',
  key: '9d4b1c83129f3de6db95faf3d539dcf1',
  base_nonce: 'ea4fd7a485ee5f1f4b62c1b7',
  exporter_secret: 'ca2410672369aae1afd6c2639f4fe34ca36d35410c090608d2924f60def17f910d7928575434d7f991b1f19d3e8358b8278ff59ced0d5eed4774cec72e12766e',
  enc_vecs: {
    0 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d30',
      nonce: 'ea4fd7a485ee5f1f4b62c1b7',
      ct: '2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d7b38a9236e'
    },
    1 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d31',
      nonce: 'ea4fd7a485ee5f1f4b62c1b6',
      ct: '10cd81e3a816d29942b602a92884348171a31cbd0f042c3057c65cd93c540943a5b05115bd520c09281061935b'
    },
    2 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d32',
      nonce: 'ea4fd7a485ee5f1f4b62c1b5',
      ct: '920743a88d8cf6a09e1a3098e8be8edd09db136e9d543f215924043af8c7410f68ce6aa64fd2b1a176e7f6b3fd'
    },
    255 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d323535',
      nonce: 'ea4fd7a485ee5f1f4b62c148',
      ct: 'd084eca50e7554bb97ba34c4482dfe32c9a2b7f3ab009c2d1b68ecbf97bee2d28cd94b6c829b96361f2701772d'
    }
  },
  max_seq: 256
})

test({
  kem_curve: :p_256,
  kem_hash: :sha256,
  kdf_hash: :sha512,
  aead_cipher: :aes_128_gcm,
  mode: MODE_AUTH_PSK,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '778f2254ae5d661d5c7fca8c4a7495a25bd13f26258e459159f3899df0de76c1',
  pkrm: '04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a111cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9',
  skrm: '00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e',
  pksm: '04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60',
  sksm: 'd743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  shared_secret: '02bee8be0dda755846115db45071c0cf59c25722e015bde1c124de849c0fea52',
  key: 'b68bb0e2fbf7431cedb46cc3b6f1fe9e',
  base_nonce: '76af62719d33d39a1cb6be9f',
  exporter_secret: '7f72308ae68c9a2b3862e686cb547b16d33d00fe482c770c4717d8b54e9b1e547244c3602bdd86d5a788a8443befea0a7658002b23f1c96a62a64986fffc511a',
  enc_vecs: {
    0 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d30',
      nonce: '76af62719d33d39a1cb6be9f',
      ct: '840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d862c2fd7d16'
    },
    1 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d31',
      nonce: '76af62719d33d39a1cb6be9e',
      ct: 'd4680a48158d9a75fd09355878d6e33997a36ee01d4a8f22032b22373b795a941b7b9c5205ff99e0ff284beef4'
    },
    2 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d32',
      nonce: '76af62719d33d39a1cb6be9d',
      ct: 'c45eb6597de2bac929a0f5d404ba9d2dc1ea031880930f1fd7a283f0a0cbebb35eac1a9ee0d1225f5e0f181571'
    },
    255 => {
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d323535',
      nonce: '76af62719d33d39a1cb6be60',
      ct: '65596b731df010c76a915c6271a438056ce65696459432eeafdae7b4cadb6290dd61e68edd4e40b659d2a8cbcc'
    }
  },
  max_seq: 256
})