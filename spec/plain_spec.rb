require 'sasl'
require 'rspec'

describe SASL::Plain do
  class MyPlainPreferences < SASL::Preferences
    def authzid
      'bob@example.com'
    end
    def username
      'bob'
    end
    def has_password?
      true
    end
    def password
      's3cr3t'
    end
  end
  preferences = MyPlainPreferences.new

  it 'should authenticate' do
    sasl = SASL::Plain.new('PLAIN', preferences)
    expect( sasl.start ).to eq ['auth', "bob@example.com\000bob\000s3cr3t"]
    expect( sasl.success?).to eq false
    expect( sasl.receive('success', nil)).to eq  nil
    expect( sasl.failure? ).to eq false
    expect( sasl.success? ).to eq true
  end

  it 'should recognize failure' do
    sasl = SASL::Plain.new('PLAIN', preferences)
    expect( sasl.start  ).to eq ['auth', "bob@example.com\000bob\000s3cr3t"]
    expect( sasl.success? ).to eq  false
    expect( sasl.failure? ).to eq false
    expect( sasl.receive('failure', 'keep-idiots-out') ).to eq nil
    expect( sasl.failure? ).to eq  true
    expect( sasl.success? ).to eq  false
  end
end
