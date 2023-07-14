require_relative 'hpke'

MODE_BASE     = 0x00
MODE_PSK      = 0x01
MODE_AUTH     = 0x02
MODE_AUTH_PSK = 0x03

def test(vec)
  hpke = HPKE.new(vec[:kem_curve], vec[:kem_hash], vec[:kdf_hash], vec[:aead_cipher])

  puts "hpke: DHKEM(#{vec[:kem_curve]}, #{vec[:kem_hash]}), #{vec[:kdf_hash]}, #{vec[:aead_cipher]}"
  puts "mode: #{vec[:mode]}"
  puts ''

  ikme = [vec[:skem]].pack('H*')
  pkr = hpke.kem.deserialize_public_key([vec[:pkrm]].pack('H*'))
  skr = hpke.kem.create_key_pair_from_secret([vec[:skrm]].pack('H*'))
  if vec[:sksm]
    sks = hpke.kem.create_key_pair_from_secret([vec[:sksm]].pack('H*'))
  end
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

load 'test_a1.rb'

puts '------------------------'

load 'test_a2.rb'

puts '------------------------'

load 'test_a3.rb'