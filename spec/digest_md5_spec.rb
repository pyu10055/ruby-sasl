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
  preferences = MyDigestMD5Preferences.new

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
    expect(response[1]).to match( /qop="auth"/ )

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
    expect( response[1]).to match( /qop="auth"/ )

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
    expect(response[1]).to match( /qop="auth"/ )
  end

  it 'should fail' do
    sasl = SASL::DigestMD5.new('DIGEST-MD5', preferences)
    expect(sasl.start).to eq ['auth', nil]
    sasl.receive('failure', 'EPIC FAIL')
    expect(sasl.failure?).to eq true
    expect(sasl.success?).to eq false
  end
end
