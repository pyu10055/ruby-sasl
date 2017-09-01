require 'digest/md5'
require 'sasl/socket'

module SASL
  ##
  # RFC 2831:
  # http://tools.ietf.org/html/rfc2831
  class DigestMD5 < Mechanism
    begin
      require 'openssl'
      ##
      # Set to +true+ if OpenSSL is available and LDAPS is supported.
      HasOpenSSL = true
    rescue LoadError
      # :stopdoc:
      HasOpenSSL = false
      # :startdoc:
    end

    attr_writer :cnonce

    def initialize(*a)
      super
      @nonce_count = 0
      preferences.config[:secure_layer]=false if preferences.config[:secure_layer]==nil
      preferences.config[:confidentiality]=preferences.config[:secure_layer] if preferences.config[:confidentiality]==nil
      preferences.config[:cipher]="rc4" if preferences.config[:confidentiality] and not preferences.config[:cipher]

      if preferences.secure_layer and not HasOpenSSL
        raise ":secure_layer in #{self.class} depends on Openssl"
      end
    end

    def start
      @state = nil
      unless defined? @nonce
        ['auth', nil]
      else
        # reauthentication
        receive('challenge', '')
      end
    end

    def receive(message_name, content)
      case message_name
      when 'challenge'
        c = decode_challenge(content)

        unless c['rspauth']
          response = {}
          if defined?(@nonce) && response['nonce'].nil?
            # Could be reauth
          else
            # No reauth:
            @nonce_count = 0
          end
          @nonce ||= c['nonce']
          response['username'] = preferences.username
          response['realm'] = c['realm'] || preferences.realm
          response['nonce'] = @nonce
          @cnonce = generate_nonce unless defined? @cnonce
          response['cnonce'] = @cnonce
          @nc = next_nc
          response['nc'] = @nc
          @qop="auth"
          if c['qop']
            c_qop = c['qop'].split(",")
          else
            c_qop = []
          end
          if preferences.secure_layer and preferences.confidentiality and c_qop.include?("auth-conf")
            response['qop'] = "auth-conf"
            response['cipher'] = preferences.config[:cipher]
          elsif preferences.secure_layer and not preferences.confidentiality and c_qop.include?("auth-int")
            response['qop'] = "auth-int"
          else
            response['qop'] = 'auth'
          end
          @cipher=response['cipher']
          @qop=response['qop']
          response['digest-uri'] = preferences.digest_uri
          response['charset'] = 'utf-8'
          @algorithm = c['algorithm'] || "md5"
          response['response'] = response_value(@algorithm, response['nonce'], response['nc'], response['cnonce'], response['qop'], response['realm'])
          result=['response', encode_response(response)]
        else
          rspauth_expected = response_value(@algorithm, @nonce, @nc, @cnonce, @qop, '')
          #p :rspauth_received=>c['rspauth'], :rspauth_expected=>rspauth_expected
          if c['rspauth'] == rspauth_expected
            result=['response', nil]
          else
            # Bogus server?
            @state = :failure
            result=['failure', nil]
          end
        end
      when 'success'
         result=super
         if preferences.secure_layer 
            securelayer_wrapper = proc {|io| DigestMD5SecureLayer.new(io, @ha1, @qop=="auth-conf",  @cipher) }
            result=['securelayer_wrapper', securelayer_wrapper]
         end      
      else
        # No challenge? Might be success or failure
        result=super
      end
      result
    end

    private

    def decode_challenge(text)
      challenge = {}
      
      state = :key
      key = ''
      value = ''

      text.scan(/./) do |ch|
        if state == :key
          if ch == '='
            state = :value
          elsif ch =~ /\S/
            key += ch
          end
          
        elsif state == :value
          if ch == ','
            challenge[key] = value
            key = ''
            value = ''
            state = :key
          elsif ch == '"' and value == ''
            state = :quote
          else
            value += ch
          end

        elsif state == :quote
          if ch == '"'
            state = :value
          else
            value += ch
          end
        end
      end
      challenge[key] = value unless key == ''
      
      #p :decode_challenge => challenge
      challenge
    end

    def encode_response(response)
      #p :encode_response => response
      response.collect do |k,v|
        if ['username', 'cnonce', 'nonce', 'digest-uri', 'authzid','realm','qop'].include? k
          v.sub!('\\', '\\\\')
          v.sub!('"', '\\"')
          "#{k}=\"#{v}\""
        else
          "#{k}=#{v}"
        end
      end.join(',')
    end

    def generate_nonce
      nonce = ''
      while nonce.length < 32
        c = rand(128).chr
        nonce += c if c =~ /^[a-zA-Z0-9]$/
      end
      nonce
    end

    ##
    # Function from RFC2831
    def self.h(s); Digest::MD5.digest(s); end
    def h(s) self.class.h(s); end
    ##
    # Function from RFC2831
    def self.hh(s); Digest::MD5.hexdigest(s); end
    def hh(s) self.class.hh(s); end

    ##
    # Calculate the value for the response field
    def response_value(algorithm, nonce, nc, cnonce, qop, realm, a2_prefix='AUTHENTICATE')
      #p :response_value => {:nonce=>nonce,
      #  :cnonce=>cnonce,
      #  :qop=>qop,
      #  :username=>preferences.username,
      #  :realm=>preferences.realm,
      #  :password=>preferences.password,
      #  :authzid=>preferences.authzid}
      a1 = "#{preferences.username}:#{realm}:#{preferences.password}"
      if algorithm.downcase == "md5-sess"
          a1 = "#{h(a1)}:#{nonce}:#{cnonce}"
      end

      if preferences.authzid
        a1 += ":#{preferences.authzid}"
      end
      @ha1=h(a1)

      a2="#{a2_prefix}:#{preferences.digest_uri}"

      qop = "missing" if not qop

      case qop.downcase
      when "auth-int", "auth-conf"
        a2 = "#{a2}:00000000000000000000000000000000"
      end

      case qop.downcase
      when "auth", "auth-int", "auth-conf"
        hh("#{hh(a1)}:#{nonce}:#{nc}:#{cnonce}:#{qop}:#{hh(a2)}")
      when "missing"
        hh("#{hh(a1)}:#{nonce}:#{hh(a2)}")
      else
        raise "Unknown qop=#{qop}"
      end
    end

    def next_nc
      @nonce_count += 1
      s = @nonce_count.to_s
      s = "0#{s}" while s.length < 8
      s
    end
  end

  class DigestMD5SecureLayer < SecureLayer
    class DigestMD5SecureLayerError < StandardError; end

    DIGEST_SESSKEY_MAGIC_CONS_C2S = "Digest session key to client-to-server signing key magic constant"
    DIGEST_SESSKEY_MAGIC_CONS_S2C = "Digest session key to server-to-client signing key magic constant"
    DIGEST_HA1_MAGIC_CONS_C2S = "Digest H(A1) to client-to-server sealing key magic constant"
    DIGEST_HA1_MAGIC_CONS_S2C = "Digest H(A1) to server-to-client sealing key magic constant"
    ONE = [1].pack("n")

    # DES does not use the last bit
    def self.des_key(key)
        key=key.bytes.to_a
        (0..(key.size)).map {|i|
            left  = (i>=1       ? ((key[i-1]<<(8-i))%256) : 0)
            right = (i<key.size ? (key[i]>>i)             : 0)
            (left | right).chr
        }.join
    end

    def initialize(io, ha1, confidentiality, cipher, is_server=false)
        super(io)
        @localseq=0
        @remoteseq=0

        @confidentiality=confidentiality

        if is_server
            @ki_send=self.class.kis(ha1)
            @ki_recv=self.class.kic(ha1)
        else
            @ki_send=self.class.kic(ha1)
            @ki_recv=self.class.kis(ha1)
        end

        if @confidentiality
          cipher.downcase!

          # adapt openssl 3des name
          ssl_cipher=cipher
          key_len=nil
          case cipher
          when "des"
            ssl_cipher="des-cbc"
          when "3des"
            ssl_cipher="des-ede-cbc"
          when /rc4-[0-9]*/
            key_bits=cipher.split("-").last.to_i
            raise "Non 8-bit multiple for key size: #{key_bits}" if not key_bits%8 == 0
            key_len=key_bits/8
            ssl_cipher="rc4"
          end

          @enc=OpenSSL::Cipher.new(ssl_cipher).encrypt
          @dec=OpenSSL::Cipher.new(ssl_cipher).decrypt

          # Force keylen size for rc4-* that is not rc-40 or rc4. Does it work?
          [@enc,@dec].each {|cp| cp.key_len = key_len } if key_len
          
          case cipher
          # For cipher "rc4-40" n is 5;
          when "rc4-40"
            n=5
          # for "rc4-56" n is 7;
          when "rc4-56"
            n=7
          # for the rest n is 16
          else
            n=16
          end

          if is_server
            @kc_send=self.class.kcs(ha1, n)
            @kc_recv=self.class.kcc(ha1, n)
          else
            @kc_send=self.class.kcc(ha1, n)
            @kc_recv=self.class.kcs(ha1, n)
          end

          # The key for the "rc-*" ciphers is all 16 bytes of Kcc or Kcs
          case cipher
          when /rc.*/
            key_len=16
            iv_len=0
          # the key for "des" is the first 7 bytes
          when "des"
            key_len=7
            iv_len=8
          when "3des"
            key_len=14
            iv_len=8
          end

          kc_send=@kc_send[0,key_len]
          kc_recv=@kc_recv[0,key_len]

          case cipher
          when "des"
            # (8 bit * 7 bytes) key must be expanded to (7-bit * 8 bytes),
            # skipping last bit
            kc_send=self.class.des_key(kc_send)
            kc_recv=self.class.des_key(kc_recv)
            key_len = 8
            # DES does not use padding here
            [@enc,@dec].each {|cp| cp.padding=0 }
          when "3des"
            # (8 bit * 7 bytes) key must be expanded to (7-bit * 8 bytes),
            # skipping last bit
            kc_send=self.class.des_key(kc_send[0,7])+self.class.des_key(kc_send[7,7])
            kc_recv=self.class.des_key(kc_recv[0,7])+self.class.des_key(kc_recv[7,7])
            key_len = 16
            # 3DES does not use padding here
            [@enc,@dec].each {|cp| cp.padding=0 }
          end

          [@enc,@dec].each {|cp| cp.key_len = key_len } if key_len

          @enc.key=kc_send
          @enc.iv=@kc_send[-iv_len,iv_len] if iv_len >0
          @dec.key=kc_recv
          @dec.iv=@kc_recv[-iv_len,iv_len] if iv_len >0
        end
    end

    def hm(ki, msg)
        OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('md5'), ki, msg)
    end

    def mac(ki, seqnum, msg)
      hm(ki, (seqnum + msg))[0..9]# + ONE + seqnum
    end

    def wrap(msg)
        seqnum=[@localseq].pack("N")
        if @confidentiality
            # SEAL(Ki, Kc, SeqNum, msg) = {CIPHER(Kc, {msg, pad, HMAC(Ki, {SeqNum, msg})[0..9])}), 0x0001, SeqNum}
            if @enc.block_size==1
                pad=""
            else
                pad_len = @enc.block_size - ((msg.size + 10) % @enc.block_size)
                pad=pad_len.chr*pad_len
            end
            buf=@enc.update(msg + pad + mac(@ki_send, seqnum, msg)) + ONE + seqnum
        else
            #MAC(Ki, SeqNum, msg) = (HMAC(Ki, {SeqNum, msg})[0..9], 0x0001, SeqNum)
            buf=msg + mac(@ki_send, seqnum, msg) + ONE + seqnum
        end
        @localseq+=1
        buf
    end

    def unwrap(buf)
        msg_seqnum=buf[-4..-1]
        # rfc2831 does not ask to check this
        #exp_seqnum=[@remoteseq].pack("N")
        #raise DigestMD5SecureLayerError, "Invalid remote sequence field! expected:#{@remoteseq}, got:#{msg_seqnum.unpack("N").first}" if not msg_seqnum == exp_seqnum
        
        msg_one=buf[-6..-5]
        raise DigestMD5SecureLayerError, "Invalid one field!" if not msg_one == ONE

        if @confidentiality
            msg_pad_mac=@dec.update(buf[0..-7])
            msg_mac=msg_pad_mac[-10..-1]

            if @enc.block_size==1
                msg=msg_pad_mac[0..-11]
            else
                pad_len=msg_pad_mac[-11].ord
                raise DigestMD5SecureLayerError, "Invalid pad size. Invalid crypto? key?" if not ((1..8).include?(pad_len))
                msg=msg_pad_mac[0..(-11-(pad_len))]
            end
        else
            msg=buf[0..-17]
            msg_mac=buf[-16..-7]
        end
        exp_mac=mac(@ki_recv, msg_seqnum, msg)
        raise DigestMD5SecureLayerError, "Invalid mac field!" if not msg_mac == exp_mac        

        @remoteseq+=1
        msg
    end

    # Kic = MD5({H(A1), "Digest session key to client-to-server signing key magic constant"})
    def self.kic(ha1)
        DigestMD5.h(ha1 + DIGEST_SESSKEY_MAGIC_CONS_C2S)
    end
    def self.kis(ha1)
        DigestMD5.h(ha1 + DIGEST_SESSKEY_MAGIC_CONS_S2C)
    end

    # Kcs = MD5({H(A1)[0..n], "Digest H(A1) to server-to-client sealing key magic constant"})
    # FYI: Specs do not specify what 0..n means. According to cyrus sasl code, n is length and not position.
    #      More like [0,n] for ruby
    def self.kcc(ha1,n=16)
        DigestMD5.h(ha1[0,n] + DIGEST_HA1_MAGIC_CONS_C2S)
    end
    def self.kcs(ha1,n=16)
        DigestMD5.h(ha1[0,n] + DIGEST_HA1_MAGIC_CONS_S2C)
    end

  end
end


