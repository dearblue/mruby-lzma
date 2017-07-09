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

assert("LZMA - stream processing (huge)") do
  unless (1 << 28).kind_of?(Integer)
    skip "[mruby is build with MRB_INT16]"
  end

  s = "123456789" * 11111111 + "ABCDEFG"
  d = ""
  LZMA::Encoder.wrap(d, preset: 1) do |lzma|
    off = 0
    slicesize = 777777
    while off < s.bytesize
      assert_equal lzma, lzma.write(s.byteslice(off, slicesize))
      off += slicesize
      slicesize = slicesize * 3 + 7
    end
  end

  assert_equal s.hash, LZMA.decode(d, s.bytesize).hash
  assert_equal s.hash, LZMA.decode(d).hash

  LZMA::Decoder.wrap(d) do |lzma|
    off = 0
    slicesize = 3
    while off < s.bytesize
      assert_equal s.byteslice(off, slicesize).hash, lzma.read(slicesize).hash
      off += slicesize
      slicesize = slicesize * 2 + 3
    end

    assert_equal nil.hash, lzma.read(slicesize).hash
  end
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
