module LZMA
  #
  # call-seq:
  #   encode(src, dest = "", (*filters,) opts = {}) -> dest
  #   encode(src, maxdest, dest = "", (*filters,) opts = {}) -> dest
  #   encode(output_io, (*filters,) opts = {}) -> instance of LZMA::Encoder
  #   encode(output_io, (*filters,) opts = {}) { |instance of LZMA::Encoder| ... } -> yeald value
  #
  # [source_string (String)]
  #   string object
  #
  # [output_io (any object)]
  #   Output port for LZMA stream.
  #   Need +.<<+ method.
  #
  # [filters]
  #
  # [opts (Hash)]
  #
  def LZMA.encode(port, *args, &block)
    if port.is_a?(String)
      Encoder.encode(port, *args)
    else
      Encoder.wrap(port, *args, &block)
    end
  end

  def LZMA.decode(port, *args, &block)
    if port.is_a?(String)
      Decoder.decode(port, *args)
    else
      Decoder.wrap(port, *args, &block)
    end
  end

  module StreamWrapper
    def wrap(*args)
      strm = new(*args)

      return strm unless block_given?

      begin
        yield strm
      ensure
        strm.close rescue nil
        strm = nil
      end
    end
  end

  Encoder.extend StreamWrapper
  Decoder.extend StreamWrapper

  def LZMA.lzma1(*args)
    LZMA1.new(*args)
  end

  def LZMA.lzma2(*args)
    LZMA2.new(*args)
  end

  def LZMA.delta(*args)
    Delta.new(*args)
  end

  def LZMA.bcj(*args)
    BCJ.new(*args)
  end
end
