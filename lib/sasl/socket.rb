module SASL
    
    class SecureLayer
        attr_reader :io

        def initialize(io)
            @io=io
        end

        def write(buf)
            wbuf = wrap(buf)
            @io.write([wbuf.size].pack("N"))
            @io.write(wbuf)
        end
    
        def read
            bsize=@io.read(4) 
            size=bsize.unpack("N")
            buf=@io.read(size.first)
            unwrap(buf)
        end

        def wrap(buf)
            raise AbstractMethod
        end

        def unwrap(buf)
            raise AbstractMethod
        end

        def close
            @io.close
        end
    end

    require "openssl"

    module Buffering
        def self.extended(base)
            class << base
                alias_method :nonbuf_read,  :read
                alias_method :nonbuf_write, :write
                alias_method :nonbuf_close, :close
            end
            base.extend(OpenSSL::Buffering)
            base.init_buffering
        end

        def init_buffering
            @eof = false
            @rbuffer = ""
            @sync = @io.sync
        end

        def sysread(size)
            nonbuf_read
        end

        def syswrite(buf)
            nonbuf_write(buf)
        end

        def sysclose
            nonbuf_close
        end
    end
end
