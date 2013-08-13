Gem::Specification.new do |s|
  s.name = 'luizluca-ruby-sasl'
  s.version = '0.0.4.0'

  s.authors = ['Stephan Maka', 'Ping Yu', 'Luiz Angelo Daros de Luca']
  s.date = '2010-10-18'
  s.description = 'Simple Authentication and Security Layer (RFC 4422)'
  s.email = 'pyu@intridea.com'
  s.test_files = %w(spec/mechanism_spec.rb
                    spec/anonymous_spec.rb
                    spec/plain_spec.rb
                    spec/digest_md5_spec.rb
                    spec/socket.rb)
  s.files = s.test_files + %w(lib/sasl/base.rb
                              lib/sasl/digest_md5.rb
                              lib/sasl/gssapi.rb
                              lib/sasl/gssspnego.rb
                              lib/sasl/anonymous.rb
                              lib/sasl/plain.rb
                              lib/sasl/base64.rb
                              lib/sasl/socket.rb
                              lib/sasl.rb
                              README.markdown)
  s.has_rdoc = false
  s.homepage = 'http://github.com/luizluca/ruby-sasl/'
  s.require_paths = ["lib"]
  s.summary = 'SASL client library'
end
