require "sasl"
require 'socket'
require 'rspec'

describe SASL::SecureLayer do

  class PlainSecureLayer < SASL::SecureLayer
    def wrap(buf)
      buf
    end
    def unwrap(buf)
      buf
    end
  end

  MSG="plaintext" if not defined? MSG
  io=StringIO.new("","w")
  sl=PlainSecureLayer.new(io)
  sl.write(MSG)
  buf=io.string

  it 'should send msg with correct size' do
    buf[0,4].unpack("N").first.should == MSG.size
  end
  it 'should send msg with the correct content' do
    msg=buf[4..-1]
    msg.bytes.to_a.should == MSG.bytes.to_a
  end

  it 'should recv msg with the correct content' do
    io=StringIO.new(buf,"r")
    sl=PlainSecureLayer.new(io)
    msg=sl.read
    msg.bytes.to_a.should == MSG.bytes.to_a
  end

  class PlainSecureLayerBuffered < PlainSecureLayer
    include SASL::Buffering
  end

  it 'should recv msg with the correct content, even when buffering' do
    io=StringIO.new(buf,"r")
    sl=PlainSecureLayerBuffered.new(io)
    MSG.each_char {|chr|
      sl.getc.ord.should == chr.ord
    }
  end

end
