Simple Authentication and Security Layer (RFC 4422) for Ruby
============================================================

Goal
----

Have a reusable library for client implementations that need to do
authentication over SASL, mainly targeted at Jabber/XMPP libraries.
New version was tested with AD LDAP.

All class carry just state, are thread-agnostic and must also work in
asynchronous environments.

Usage
-----

Derive from **SASL::Preferences** and overwrite the methods. Then,
create a mechanism instance:

    # mechanisms => ['DIGEST-MD5', 'PLAIN']
    sasl = SASL.new(mechanisms, my_preferences)
    content_to_send = sasl.start
    # [...]
    content_to_send = sasl.challenge(received_content)

LDAP example (without secure_layer):

    opts = {:digest_uri =>"ldap/myhost.mydomain.com",
            :username => "username",
            :password => "password",
            }
    sasl = SASL.new_mechanism('DIGEST-MD5', SASL::Preferences.new(opts))
    sasl.start
    ...get cred...  
    response = sasl.receive("challenge", cred)
    ...answer response[1]...  
    ...get result...  
    response = sasl.receive("success")

LDAP example (with secure_layer):

    opts = {:digest_uri =>"ldap/myhost.mydomain.com",
            :username => "username",
            :password => "password",
            :secure_layer => true,
            :confidentiality => true, #optional
            :cipher => "rc4",         #optional 
            }
    sasl = SASL.new_mechanism('DIGEST-MD5', SASL::Preferences.new(opts))
    sasl.start
    ...get cred...  
    response = sasl.receive("challenge", cred)
    ...answer response[1]...  
    ...get result...  
    response = sasl.receive("success")
    securelayer_wrapper = response[1]
    secured_io = securelayer_wrapper.call(io)
    ...
 
secure_io is limited to some basic methods (read, write and close). SASL::Buffering
can be used to add extra methods (like getc):

    secured_io.extend(SASL::Buffering)

