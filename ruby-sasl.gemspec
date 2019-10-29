Gem::Specification.new do |s|
  s.name = 'pyu-ruby-sasl'
  s.version = '0.0.3.3'

  s.authors = ['Stephan Maka', 'Ping Yu']
  s.date = '2010-10-18'
  s.description = 'Simple Authentication and Security Layer (RFC 4422)'
  s.email = 'pyu@intridea.com'
  s.test_files = %w(spec/mechanism_spec.rb
                    spec/anonymous_spec.rb
                    spec/plain_spec.rb
                    spec/digest_md5_spec.rb)
  s.files = s.test_files + %w(lib/sasl/base.rb
                              lib/sasl/digest_md5.rb
                              lib/sasl/anonymous.rb
                              lib/sasl/plain.rb
                              lib/sasl/base64.rb
                              lib/sasl.rb
                              README.markdown)
  s.has_rdoc = false
  s.homepage = 'http://github.com/pyu10055/ruby-sasl/'
  s.require_paths = ["lib"]
  s.summary = 'SASL client library'
  s.license = 'MIT'
end
