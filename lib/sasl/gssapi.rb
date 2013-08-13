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
        preferences.config[:gss_opts] = {} if not preferences.config.include? :gss_opts    
        preferences.config[:secure_layer] = false if preferences.config[:secure_layer]==nil
    end

    def start
        @state = :authneg
        (@service,@host)=preferences.digest_uri.split("/")
        @cli = GSSAPI::Simple.new(@host, @service)
        tok = @cli.init_context(nil, preferences.gss_opts)
        ['auth', tok ]
    end

    def receive(message_name, content)
      case message_name
      when 'challenge'
        case @state
        when :authneg
            if @cli.init_context(content, preferences.gss_opts)
                if false #http
                    @state = :waiting_result
                else
                    @state = :ssfcap
                end
            else
                @state = :failure
            end
            response = nil  
        when :ssfcap
            ssf = @cli.unwrap_message(content)
            if not ssf.size == 4
                raise "token too short or long (#{ssf.size}). Should be 4."
            end

            if not preferences.secure_layer 
                # No security wanted
                response = @cli.wrap_message(0)
            else
                response = @cli.wrap_message(ssf)
            end
            @state = :waiting_result
        else
            raise "Invalid state #{@state}. Did you called start method?"
        end
        result=['response', response]
      when 'success'
         result=super
         if preferences.secure_layer 
            securelayer_wrapper = proc {|io| SASL::GssSecureLayer.new(io,@cli) }
            result=['securelayer_wrapper', securelayer_wrapper]
         end
      else
        result=super
      end
      result
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

