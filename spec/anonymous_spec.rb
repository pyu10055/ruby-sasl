require 'sasl'
require 'rspec'

describe SASL::Anonymous do
  class MyAnonymousPreferences < SASL::Preferences
    def username
      'bob'
    end
  end
  preferences = MyAnonymousPreferences.new

  it 'should authenticate anonymously' do
    sasl = SASL::Anonymous.new('ANONYMOUS', preferences)
    expect(sasl.start).to eq ['auth', 'bob']
    expect(sasl.success?).to eq false
    expect(sasl.receive('success', nil)).to eq nil
    expect(sasl.success?).to eq true
  end
end
