require 'openssl'
require_relative 'kem'
require_relative 'util'

class HPKE
  include Util

  attr_reader :aead_name, :n_k, :n_n, :n_t

  MODES = {
    base: 0x00,
    auth: 0x01,
    psk: 0x02,
    auth_psk: 0x03
  }
  CIPHERS = {
    aes_128_gcm: {
      name: 'aes-128-gcm',
      aead_id: 0x0001,
      n_k: 16,
      n_n: 12,
      n_t: 16
    },
    aes_256_gcm: {
      name: 'aes-256-gcm',
      aead_id: 0x0002,
      n_k: 32,
      n_n: 12,
      n_t: 16
    },
    chacha20_poly1305: {
      name: 'chacha20-poly1305',
      aead_id: 0x0003,
      n_k: 32,
      n_n: 12,
      n_t: 16
    },
    export_only: {
      aead_id: 0xffff
    }
  }
  HASHES = {
    sha256: {
      name: 'SHA256',
      kdf_id: 1
    },
    sha384: {
      name: 'SHA384',
      kdf_id: 2
    },
    sha512: {
      name: 'SHA512',
      kdf_id: 3
    }
  }

  def initialize(mode, kem, kdf_hash, aead_cipher)
    raise Exception.new('Wrong mode') if !MODES.keys.include?(mode)
    raise Exception.new('Wrong AEAD cipher name') if CIPHERS[aead_cipher].nil?

    @hkdf = HKDF.new(kdf_hash)
    @dhkem = kem
    @aead_name = CIPHERS[aead_cipher][:name]
    @aead_id = CIPHERS[aead_cipher][:aead_id]
    @n_k = CIPHERS[aead_cipher][:n_k]
    @n_n = CIPHERS[aead_cipher][:n_n]
    @n_t = CIPHERS[aead_cipher][:n_t]
  end

  def suite_id
    'HPKE' + i2osp(kem.kem_id, 2) + i2osp(@dhkem.kdf_id, 2) + i2osp(@aead_id, 2)
  end

  DEFAULT_PSK = ''
  DEFAULT_PSK_ID = ''

  def verify_psk_inputs(mode, psk, psk_id)
    got_psk = (psk != DEFAULT_PSK)
    got_psk_id = (psk_id != DEFAULT_PSK_ID)

    raise Exception.new('Inconsistent PSK inputs') if got_psk != got_psk_id
    raise Exception.new('PSK input provided when not needed') if got_psk && [MODE_BASE, MODE_AUTH].include?(mode)
    raise Exception.new('Missing required PSK input') if !got_psk && [MODE_PSK, MODE_AUTH_PSK].include?(mode)

    true
  end

  def setup_base_s(pk_r, info)
    encap_result = @dhkem.encap(pk_r)
    {
      enc: encap_result[:enc],
      key_schedule_s: key_schedule_s(MODES[:base], encap_result[:shared_secret], info, DEFAULT_PSK, DEFAULT_PSK_ID)
    }
  end

  def setup_base_r(enc, sk_r, info)
    shared_secret = @dhkem.decap(enc, sk_r)
    key_schedule_r(MODES[:base], shared_secret, info, DEFAULT_PSK, DEFAULT_PSK_ID)
  end

  def key_schedule(mode, shared_secret, info, psk = '', psk_id = '')
    verify_psk_inputs(mode, psk, psk_id)

    psk_id_hash = @hkdf.labeled_extract('', 'psk_id_hash', psk_id, suite_id)
    info_hash = @hkdf.labeled_extract('', 'info_hash', info, suite_id)
    key_schedule_context = mode.chr + psk_id_hash + info_hash

    secret = @hkdf.labeled_extract(shared_secret, 'secret', psk, suite_id)

    key = @hkdf.labeled_expand(secret, 'key', key_schedule_context, @n_k, suite_id)
    base_nonce = @hkdf.labeled_expand(secret, 'base_nonce', key_schedule_context, @n_n, suite_id)
    exporter_secret = @hkdf.labeled_expand(secret, 'exp', key_schedule_context, @hkdf.n_h, suite_id)

    {
      key: key,
      base_nonce: base_nonce,
      sequence_number: 0,
      exporter_secret: exporter_secret
    }
  end

  def key_schedule_s(mode, shared_secret, info, psk = '', psk_id = '')
    ks = key_schedule(mode, shared_secret, info, psk, psk_id)
    HPKE::ContextS.new(ks, self)
  end

  def key_schedule_r(mode, shared_secret, info, psk = '', psk_id = '')
    ks = key_schedule(mode, shared_secret, info, psk, psk_id)
    HPKE::ContextR.new(ks, self)
  end
end

class HPKE::Context
  attr_reader :key, :base_nonce, :sequence_number, :exporter_secret

  def initialize(initializer_hash, hpke)
    @hpke = hpke
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
    raise Exception.new('MessageLimitReachedError') if @sequence_number >= (1 << (8 * @hpke.n_n)) - 1

    @sequence_number += 1
  end
end

class HPKE::ContextS < HPKE::Context
  def seal(aad, pt)
    ct = cipher_seal(@key, compute_nonce(@sequence_number), aad, pt)
    increment_seq
    ct
  end

  private

  def cipher_seal(key, nonce, aad, pt)
    cipher = OpenSSL::Cipher.new(@hpke.aead_name)
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_data = aad
    cipher.padding = 0
    s = cipher.update(pt) << cipher.final
    s + cipher.auth_tag
  end
end

class HPKE::ContextR < HPKE::Context
  def open(aad, ct)
    pt = cipher_open(@key, compute_nonce(@sequence_number), aad, ct)
    # TODO: catch openerror then send out own openerror
    increment_seq
    pt
  end

  private

  def cipher_open(key, nonce, aad, ct)
    ct_body = ct[0, ct.length - @hpke.n_t]
    tag = ct[-@hpke.n_t, @hpke.n_t]
    cipher = OpenSSL::Cipher.new(@hpke.aead_name)
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    cipher.auth_data = aad
    cipher.padding = 0
    cipher.update(ct_body) << cipher.final
  end
end