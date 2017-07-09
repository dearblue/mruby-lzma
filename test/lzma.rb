#!ruby

s = "123456789" * 1111

assert("LZMA - one step process") do
  d = ""
  assert_equal String, LZMA.encode(s).class
  assert_equal String, LZMA.encode(s, 20000).class
  assert_equal d.object_id, LZMA.encode(s, d).object_id
  assert_equal d.object_id, LZMA.decode(LZMA.encode(s), d).object_id
  assert_equal s.byteslice(0, 2000), LZMA.decode(LZMA.encode(s), 2000)
  assert_equal s, LZMA.decode(LZMA.encode(s, LZMA.lzma2(1)))
  assert_equal s, LZMA.decode(LZMA.encode(s, LZMA.delta(1), LZMA.lzma2(1)))
end

assert("LZMA - streaming process") do
  d = ""
  lzma = LZMA::Encoder.new(d)
  lzma.close

  assert_equal "", LZMA.decode(d)

  d = ""
  lzma = LZMA::Encoder.new(d, preset: 0)
  t = 9
  t.times { lzma.write s }
  lzma.close

  ss = s * t
  dd = LZMA.decode(d)
  assert_equal LZMA.crc64_hexdigest(ss), LZMA.crc64_hexdigest(dd)

  LZMA::Decoder.open(d) do |xz|
    assert_equal LZMA.crc64(ss.byteslice(0, 29)), LZMA.crc64(xz.read(29))
    assert_equal LZMA.crc64(ss.byteslice(29, 49)), LZMA.crc64(xz.read(49))
    assert_equal LZMA.crc64(ss.byteslice(78, 599)), LZMA.crc64(xz.read(599))
    assert_equal LZMA.crc64(ss.byteslice(677..-1)), LZMA.crc64(xz.read)
  end

  true
end

assert("LZMA - one step process as raw stream") do
  skip "(NOT IMPLEMENTED YET)"

  s = "123456789" * 99999
  d = ""
  filter = [LZMA.delta, LZMA.lzma2(9, dictsize: 4 << 20)]
  assert_equal d.object_id, LZMA.raw_encode(s, d, *filter).object_id
  assert_equal d.object_id, LZMA.raw_decode(LZMA.raw_encode(s, *filter), d, *filter).object_id
  assert_equal s, LZMA.raw_decode(LZMA.raw_encode(s, *filter), *filter)
end
