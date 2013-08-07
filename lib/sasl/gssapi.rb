require 'sasl/socket'

module SASL

  class GssApi < Mechanism

    begin
      # gssapi (1.1.2) 
      require 'gssapi'
      HasGSSAPI = true
    rescue LoadError
      # :stopdoc:
      HasGSSAPI = false
      # :startdoc:
    end

    def initialize(*args)
        raise LoadError.new("You need gssapi gem in order to use this class") if not HasGSSAPI
        super(*args)
    end

    def start
        @state = :authneg
        (@service,@host)=preferences.digest_uri.split("/")
        @cli = GSSAPI::Simple.new(@host, @service)
        tok = @cli.init_context
        ['auth', tok ]
    end

    def receive(message_name, content)
      if message_name == 'challenge'
        case @state
        when :authneg
            if @cli.init_context(content)
                if false #http
                    @state = :success
                else
                    @state = :ssfcap
                end
            else
                @state = :failure
            end
            response = nil  
        when :ssfcap
            tok = @cli.unwrap_message(content)
            if not tok.size == 4
                raise "token too short or long (#{tok.size}). Should be 4."
            end

            # I dunno that to do with tok yet but sending it back is working
            response = @cli.wrap_message(tok)
            @state = :success
            
            securelayer_wrapper = proc {|io| SASL::GssSecureLayer.new(io,@cli) }
            response = [response, securelayer_wrapper]
        else
            raise "Invalid state #{@state}. Did you called start method?"
        end
        ['response', response]
      else
        super
      end
    end
  end

  class GssSecureLayer < SecureLayer
    def initialize(io,ctx)
        super(io)
        @ctx=ctx
    end

    def wrap(buf)
        @ctx.wrap_message(buf)
    end
   
    def unwrap(buf)
        @ctx.unwrap_message(buf)
    end
  end
end

