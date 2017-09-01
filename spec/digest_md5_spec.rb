require 'sasl'
require 'rspec'

describe SASL::DigestMD5 do
  # Preferences from http://tools.ietf.org/html/rfc2831#section-4
  class MyDigestMD5Preferences < SASL::Preferences
    attr_writer :serv_type
    def realm
      'elwood.innosoft.com'
    end
    def digest_uri
      "#{@serv_type}/elwood.innosoft.com"
    end
    def username
      'chris'
    end
    def has_password?
      true
    end
    def password
      'secret'
    end
  end
  preferences = MyDigestMD5Preferences.new({})

  it 'should authenticate (1)' do
    preferences.serv_type = 'imap'
    sasl = SASL::DigestMD5.new('DIGEST-MD5', preferences)
    expect(sasl.start).to eq ['auth', nil]
    sasl.cnonce = 'OA6MHXh6VqTrRk'
    response = sasl.receive('challenge',
                            'realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",
                             algorithm=md5-sess,charset=utf-8')
    expect(response[0]).to eq 'response'
    expect(response[1]).to match( /charset="?utf-8"?/ )
    expect(response[1]).to match( /username="?chris"?/ )
    expect(response[1]).to match( /realm="?elwood.innosoft.com"?/ )
    expect(response[1]).to match( /nonce="?OA6MG9tEQGm2hh"?/ )
    expect(response[1]).to match( /nc="?00000001"?/ )
    expect(response[1]).to match( /cnonce="?OA6MHXh6VqTrRk"?/ )
    expect(response[1]).to match( /digest-uri="?imap\/elwood.innosoft.com"?/ )
    expect(response[1]).to match( /response=d388dad90d4bbd760a152321f2143af7"?/ )
    expect(response[1]).to match( /qop="?auth"?/ )

    expect(sasl.receive('challenge',
                 'rspauth=ea40f60335c427b5527b84dbabcdfffd')).to eq ['response', nil]
    expect(sasl.receive('success', nil)).to eq nil
    expect(sasl.success?).to eq true
  end

  it 'should authenticate (2)' do
    preferences.serv_type = 'acap'
    sasl = SASL::DigestMD5.new('DIGEST-MD5', preferences)
    expect( sasl.start).to eq ['auth', nil]
    sasl.cnonce = 'OA9BSuZWMSpW8m'
    response = sasl.receive('challenge',
                            'realm="elwood.innosoft.com",nonce="OA9BSXrbuRhWay",qop="auth",
                             algorithm=md5-sess,charset=utf-8')
    expect( response[0]).to eq 'response'
    expect( response[1]).to match( /charset="?utf-8"?/ )
    expect( response[1]).to match( /username="?chris"?/ )
    expect( response[1]).to match( /realm="?elwood.innosoft.com"?/ )
    expect( response[1]).to match( /nonce="?OA9BSXrbuRhWay"?/ )
    expect( response[1]).to match( /nc="?00000001"?/ )
    expect( response[1]).to match( /cnonce="?OA9BSuZWMSpW8m"?/ )
    expect( response[1]).to match( /digest-uri="?acap\/elwood.innosoft.com"?/ )
    expect( response[1]).to match( /response=6084c6db3fede7352c551284490fd0fc"?/ )
    expect( response[1]).to match( /qop="?auth"?/ )

    expect( sasl.receive('challenge',
                 'rspauth=2f0b3d7c3c2e486600ef710726aa2eae')).to eq ['response', nil]
    expect( sasl.receive('success', nil)).to eq nil
    expect( sasl.success?).to eq true
  end

  it 'should reauthenticate' do
    preferences.serv_type = 'imap'
    sasl = SASL::DigestMD5.new('DIGEST-MD5', preferences)
    expect(sasl.start).to eq ['auth', nil]
    sasl.cnonce = 'OA6MHXh6VqTrRk'
    sasl.receive('challenge',
                 'realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",
                  algorithm=md5-sess,charset=utf-8')
    # reauth:
    response = sasl.start
    expect(response[0]).to eq 'response'
    expect(response[1]).to match( /charset="?utf-8"?/ )
    expect(response[1]).to match( /username="?chris"?/ )
    expect(response[1]).to match( /realm="?elwood.innosoft.com"?/ )
    expect(response[1]).to match( /nonce="?OA6MG9tEQGm2hh"?/ )
    expect(response[1]).to match( /nc="?00000002"?/ )
    expect(response[1]).to match( /cnonce="?OA6MHXh6VqTrRk"?/ )
    expect(response[1]).to match( /digest-uri="?imap\/elwood.innosoft.com"?/ )
    expect(response[1]).to match( /response=b0b5d72a400655b8306e434566b10efb"?/ ) # my own result
    expect(response[1]).to match( /qop="?auth"?/ )
  end

  it 'should fail' do
    sasl = SASL::DigestMD5.new('DIGEST-MD5', preferences)
    expect(sasl.start).to eq ['auth', nil]
    sasl.receive('failure', 'EPIC FAIL')
    expect(sasl.failure?).to eq true
    expect(sasl.success?).to eq false
  end
end

describe SASL::DigestMD5SecureLayer do
  HA1="1234567890ABCDEF" if not defined? HA1
  MSG="plaintext" if not defined? MSG

  it 'DigestMD5SecureLayer.kic should generate correct KIC' do
    result   = SASL::DigestMD5SecureLayer.kic(HA1)
    expected = "\xC6 6/\xFD\xD5\x0F\xF6E7=\x82Y\x16\r\x03"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  it 'DigestMD5SecureLayer.kcc should generate correct KIS' do
    result   = SASL::DigestMD5SecureLayer.kis(HA1)
    expected = "\x10\xBED)v\x1E#I\xA5\xF8RR\xF4\x80\t_"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  it 'DigestMD5SecureLayer.kcc should generate correct KCC (n=16)' do
    result   = SASL::DigestMD5SecureLayer.kcc(HA1,16)
    expected = "a\xA2\xF5\x9C\xD2g\x85\xF3\eOZ\x10^\xF9\x97v"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  it 'DigestMD5SecureLayer.kcc should generate correct KCC (n=7)' do
    result   = SASL::DigestMD5SecureLayer.kcc(HA1,7)
    expected = "E{\xC1\xE4\x14W\x12\xE4\x88d=\xA5\xFCY5M"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  it 'DigestMD5SecureLayer.kcc should generate correct KCC (n=5)' do
    result   = SASL::DigestMD5SecureLayer.kcc(HA1,5)
    expected = "\xD3\xBCK\x86\xF4\xC1\xEF\xA9\xAE\xCC\xB9K\xA4KJ\x99"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  it 'DigestMD5SecureLayer.kcs should generate correct KCS (n=5)' do
    result   = SASL::DigestMD5SecureLayer.kcs(HA1,16)
    expected = "\x18g\xDA\xD2\x99\xC41\xD3\x11\x0E\x8B\xA2\xAC&\x82\xA3"
    expected.bytes.to_a.should == result.bytes.to_a
  end

  ###################
  # Integrity tests
  ###################
  function="DigestMD5SecureLayer.wrap (integrity mode, client)"
  io=StringIO.new("", "w")
  dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, false)
  dg.write(MSG)
  buf=io.string

  # Client mode (write)
  it 'should generate correct bufsize' do
    result   = buf[0,4]
    expected = "\x00\x00\x00\x19" 
    expected.bytes.to_a.should == result.bytes.to_a
  end
  # I should tested this twice to see if it increments
  it 'should generate correct seq number' do
    result   = buf[-4,4]
    expected = "\x00\x00\x00\x00" 
    expected.bytes.to_a.should == result.bytes.to_a
  end
  it 'should generate one number' do
    result   = buf[-6,2]
    expected = "\x00\x01"
    expected.bytes.to_a.should == result.bytes.to_a
  end
  it 'should generate correct MAC field ' do
    result   = buf[-16,10]
    expected = "b\xD6\xD1#\xCF\xCE7\x97\x1D\xD4"
    expected.bytes.to_a.should == result.bytes.to_a
  end
  it 'should preserve original msg content' do
    result   = buf[4,9]
    expected = MSG
    expected.bytes.to_a.should == result.bytes.to_a
  end

  # Server mode (read)
  it 'should return only the original msg content' do
    io=StringIO.new(buf, "r")
    dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, true)
    result = dg.read
    expected = MSG 
    expected.bytes.to_a.should == result.bytes.to_a
  end
  it 'should raise exception when msgsize is changed' do
     buf_def=buf.clone
     buf_def[4]="\x18"
     io=StringIO.new(buf_def, "r")
     dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, true)
     expect { dg.read }.to raise_error SASL::DigestMD5SecureLayer::DigestMD5SecureLayerError
  end
  it 'should raise exception when one field is missing' do
     buf_def=buf.clone
     buf_def[-5]="\x02"
     io=StringIO.new(buf_def, "r")
     dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, true)
     expect { dg.read }.to raise_error SASL::DigestMD5SecureLayer::DigestMD5SecureLayerError
  end
  it 'should raise exception when MAC is changed' do
     buf_def=buf.clone
     buf_def[-16]="\x0F"
     io=StringIO.new(buf_def, "r")
     dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, true)
     expect { dg.read }.to raise_error SASL::DigestMD5SecureLayer::DigestMD5SecureLayerError
  end
  it 'should raise exception when msg content is changed' do
     buf_def=buf.clone
     buf_def[4]="P"
     io=StringIO.new(buf_def, "r")
     dg=SASL::DigestMD5SecureLayer.new(io, HA1, false, nil, true)
     expect { dg.read }.to raise_error SASL::DigestMD5SecureLayer::DigestMD5SecureLayerError
  end

  ###########################
  # Confidentiality tests
  ###########################
  ["rc4","rc4-40","rc4-56","des","3des"].each do
    |cipher|
     it "should encrypt and decrypt messages with #{cipher} cipher" do
       # client
       io=StringIO.new("", "w")
       dg=SASL::DigestMD5SecureLayer.new(io, HA1, true, cipher, false)
       dg.write(MSG)
       buf=io.string

       # server
       io=StringIO.new(buf, "r")
       dg=SASL::DigestMD5SecureLayer.new(io, HA1, true, cipher, true)
       result = dg.read
       expected = MSG 
       expected.bytes.to_a.should == result.bytes.to_a
     end
  end

end
