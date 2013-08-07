module SASL

  class GssSpnego < Mechanism

    begin
      # rubyntlm (0.3.3)
      require 'net/ntlm'
      HasNTLM = true
    rescue LoadError
      # :stopdoc:
      HasNTLM = false
      # :startdoc:
    end

    def initialize(*args)
        raise LoadError.new("You need rubyntlm gem in order to use this class") if not HasNTLM
        super(*args)
    end

    def start
      @state = nil
      ['auth', Net::NTLM::Message::Type1.new.serialize]
    end

    def receive(message_name, content)
      if message_name == 'challenge'
        t2_msg = Net::NTLM::Message.parse(content)
        t3_msg = t2_msg.response({ :user => preferences.username, :password => preferences.password},
                                 { :ntlmv2 => true })
        p message_name
        ['response', t3_msg.serialize]
      else
        super
      end
    end
  end
end

