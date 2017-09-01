module SASL
    
    class SecureLayer
        attr_reader :io

        def initialize(io)
            @io=io
        end

        def write(buf)
            wbuf = wrap(buf)
            @io.syswrite([wbuf.size].pack("N"))
            @io.syswrite(wbuf)
        end
    
        def read
            bsize=@io.sysread(4)
            raise "SASL Buffer size is nil!" if bsize==nil
            size=bsize.unpack("N")
            buf=@io.sysread(size.first)
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

    module Buffering
        begin
          require 'openssl'
          HasOpenSSL = true
        rescue LoadError
          # :stopdoc:
          HasOpenSSL = false
          # :startdoc:
        end

        # When an object is extended
        def self.extended(base)
            class << base
                Buffering.included(self)
            end
            base.initialize_buffering
        end
      
        # When a class is extended
        def self.included(base)
            raise LoadError.new("SASL::Buffering depends on OpenSSL::Buffering") if not HasOpenSSL
            base.class_eval do
                alias_method :nonbuf_read,  :read
                alias_method :nonbuf_write, :write
                alias_method :nonbuf_close, :close

                # OpenSSL::Buffering replaces initialize. I should save it
                alias_method :orig_initialize, :initialize
                include OpenSSL::Buffering
                alias_method :initialize_buffering, :initialize
                public :initialize_buffering
                
                def initialize(*args)
                    orig_initialize(*args)
                    initialize_buffering
                end
            end
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
