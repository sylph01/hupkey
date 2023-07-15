test({
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :export_only,
  mode: MODE_BASE,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed',
  pkrm: '194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664',
  skrm: '33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848',
  psk: '',
  psk_id: '',
  shared_secret: 'e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66',
  key: '',
  base_nonce: '',
  exporter_secret: '79dc8e0509cf4a3364ca027e5a0138235281611ca910e435e8ed58167c72f79b',
  enc_vecs: [
    {
      exporter_context: '',
      l: 32,
      exported_value: '7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36'
    },
    {
      exporter_context: '00',
      l: 32,
      exported_value: 'd5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0'
    },
    {
      exporter_context: '54657374436f6e74657874',
      l: 32,
      exported_value: 'ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e'
    }
  ]
})

test({
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :export_only,
  mode: MODE_PSK,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '1d72396121a6a826549776ef1a9d2f3a2907fc6a38902fa4e401afdb0392e627',
  pkrm: 'd53af36ea5f58f8868bb4a1333ed4cc47e7a63b0040eb54c77b9c8ec456da824',
  skrm: '98f304d4ecb312689690b113973c61ffe0aa7c13f2fbe365e48f3ed09e5a6a0c',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  shared_secret: '024573db58c887decb4c57b6ed39f2c9a09c85600a8a0ecb11cac24c6aaec195',
  key: '',
  base_nonce: '',
  exporter_secret: '04261818aeae99d6aba5101bd35ddf3271d909a756adcef0d41389d9ed9ab153',
  enc_vecs: [
    {
      exporter_context: '',
      l: 32,
      exported_value: 'be6c76955334376aa23e936be013ba8bbae90ae74ed995c1c6157e6f08dd5316'
    },
    {
      exporter_context: '00',
      l: 32,
      exported_value: '1721ed2aa852f84d44ad020c2e2be4e2e6375098bf48775a533505fd56a3f416'
    },
    {
      exporter_context: '54657374436f6e74657874',
      l: 32,
      exported_value: '7c9d79876a288507b81a5a52365a7d39cc0fa3f07e34172984f96fec07c44cba'
    }
  ]
})

test({
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :export_only,
  mode: MODE_AUTH,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: '83d3f217071bbf600ba6f081f6e4005d27b97c8001f55cb5ff6ea3bbea1d9295',
  pkrm: 'ffd7ac24694cb17939d95feb7c4c6539bb31621deb9b96d715a64abdd9d14b10',
  skrm: 'ed88cda0e91ca5da64b6ad7fc34a10f096fa92f0b9ceff9d2c55124304ed8b4a',
  pksm: '89eb1feae431159a5250c5186f72a15962c8d0debd20a8389d8b6e4996e14306',
  sksm: 'c85f136e06d72d28314f0e34b10aadc8d297e9d71d45a5662c2b7c3b9f9f9405',
  psk: '',
  psk_id: '',
  shared_secret: 'e204156fd17fd65b132d53a0558cd67b7c0d7095ee494b00f47d686eb78f8fb3',
  key: '',
  base_nonce: '',
  exporter_secret: '276d87e5cb0655c7d3dad95e76e6fc02746739eb9d968955ccf8a6346c97509e',
  enc_vecs: [
    {
      exporter_context: '',
      l: 32,
      exported_value: '83c1bac00a45ed4cb6bd8a6007d2ce4ec501f55e485c5642bd01bf6b6d7d6f0a'
    },
    {
      exporter_context: '00',
      l: 32,
      exported_value: '08a1d1ad2af3ef5bc40232a64f920650eb9b1034fac3892f729f7949621bf06e'
    },
    {
      exporter_context: '54657374436f6e74657874',
      l: 32,
      exported_value: 'ff3b0e37a9954247fea53f251b799e2edd35aac7152c5795751a3da424feca73'
    }
  ]
})

test({
  kem_curve: :x25519,
  kem_hash: :sha256,
  kdf_hash: :sha256,
  aead_cipher: :export_only,
  mode: MODE_AUTH_PSK,
  info: '4f6465206f6e2061204772656369616e2055726e',
  skem: 'a2b43f5c67d0d560ee04de0122c765ea5165e328410844db97f74595761bbb81',
  pkrm: 'f47cd9d6993d2e2234eb122b425accfb486ee80f89607b087094e9f413253c2d',
  skrm: 'c4962a7f97d773a47bdf40db4b01dc6a56797c9e0deaab45f4ea3aa9b1d72904',
  pksm: '29a5bf3867a6128bbdf8e070abe7fe70ca5e07b629eba5819af73810ee20112f',
  sksm: '6175b2830c5743dff5b7568a7e20edb1fe477fb0487ca21d6433365be90234d0',
  psk: '0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82',
  psk_id: '456e6e796e20447572696e206172616e204d6f726961',
  shared_secret: 'd69246bcd767e579b1eec80956d7e7dfbd2902dad920556f0de69bd54054a2d1',
  key: '',
  base_nonce: '',
  exporter_secret: '695b1faa479c0e0518b6414c3b46e8ef5caea04c0a192246843765ae6a8a78e0',
  enc_vecs: [
    {
      exporter_context: '',
      l: 32,
      exported_value: 'dafd8beb94c5802535c22ff4c1af8946c98df2c417e187c6ccafe45335810b58'
    },
    {
      exporter_context: '00',
      l: 32,
      exported_value: '7346bb0b56caf457bcc1aa63c1b97d9834644bdacac8f72dbbe3463e4e46b0dd'
    },
    {
      exporter_context: '54657374436f6e74657874',
      l: 32,
      exported_value: '84f3466bd5a03bde6444324e63d7560e7ac790da4e5bbab01e7c4d575728c34a'
    }
  ]
})
