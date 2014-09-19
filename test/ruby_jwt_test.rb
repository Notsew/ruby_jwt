require 'test_helper'

class RubyJwtTest < ActiveSupport::TestCase
	
  def setup
	@header = {:typ => "JWT", :alg => "HS256"}
	@payload = {:name => "Chris", :role =>"admin"}
	@payload_options = {:iss => "my_app", :aud => "your_app", :exp => 5000} 
	@secret = "secret"
	@key = OpenSSL::PKey::RSA.new(2048) 
  end

  test "should encode and decode and verify hmac" do
  	jwt = JWT.sign(@payload,@secret,@payload_options,nil)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,@secret,@payload_options)
    assert_equal(@header, verified_jwt.header) and assert_equal(@payload,decoded.payload)
  end

   test "should encode and decode none" do
  	@header = {:typ => "JWT", :alg => "none"}
  	jwt = JWT.sign(@payload,nil,@payload_options,@header)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,nil,@payload_options)
    assert_equal(@header, verified_jwt.header) and assert_equal(@payload,decoded.payload)
  end

  test "should encode and decode RSA" do
  	@header = {:typ => "JWT", :alg => "RS384"}
  	jwt = JWT.sign(@payload,@key,@payload_options,@header)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,@key,@payload_options)
    assert_equal(@header, verified_jwt.header) and assert_equal(@payload,decoded.payload)
  end

  test "should encode and decode ECDSA" do
    pk = OpenSSL::PKey::EC.new("prime192v1")
    pk.generate_key
    @header = {:typ => "JWT", :alg => "ES384"}
    jwt = JWT.sign(@payload,pk,@payload_options,@header)
    decoded = JWT.decode(jwt)
    verified_jwt = JWT.verify(jwt,pk,@payload_options)
    assert_equal(@header, verified_jwt.header) and assert_equal(@payload,decoded.payload)
  end

  test "decodes and verifies existing token" do
    secret = "0zWThVpyGq4QujsMHzTqNYZUbeXGB2Sa"
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJDaHJpcyBXZXN0b24iLCJpYXQiOjE0MTA2MTc1NzQsImV4cCI6MTY5MDUwNzYzOTcsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJHaXZlbk5hbWUiOiJKb2hubnkiLCJTdXJuYW1lIjoiUm9ja2V0IiwiRW1haWwiOiJqcm9ja2V0QGV4YW1wbGUuY29tIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.llRwkrzrkAu_n4XFGvZpHR3J_p_Ow3er7LxJBZS-4M4"    
    decoded = JWT.decode(token)
    verified = JWT.verify(token,secret,{:iss => "Chris Weston", :aud => ["www.example.com", "mysite.com"]})
    assert_equal("Chris Weston",verified.payload[:iss]) and assert_equal(true, (verified.payload[:Role].include? "Manager"))
  end

  test "returns false if expired" do
    @payload_options[:exp] = - 50
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    assert_raises(JWT::VerificationError){ verified_jwt = JWT.verify(jwt,@secret,@payload_options)}
  end

  test "returns false if before nbf" do
    @payload_options[:nbf] = 50
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    assert_raises(JWT::VerificationError){ verified_jwt = JWT.verify(jwt,@secret,@payload_options)}
  end

  test "returns false if wrong audience" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    
    assert_raises(JWT::VerificationError){ verified_jwt = JWT.verify(jwt,@secret,{:aud => "not_your_app"})}  
  end

  test "returns false if wrong issuer" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    assert_raises(JWT::VerificationError){verified_jwt = JWT.verify(jwt,@secret,{:iss => "not_my_app"})}    
  end

  test "returns false if invalid signature" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    assert_raises(JWT::VerificationError){verified_jwt = JWT.verify(jwt,"bad_secret")}    
  end

  test "returns sign error for no key" do
    assert_raises(JWT::SignError){jwt = JWT.sign(@payload,nil,@payload_options,@header)}
  end

  test "returns not implemented error for unsupported algorithm" do
    assert_raises(JWT::SignError){@header[:alg] = "HS422";jwt = JWT.sign(@payload,@secret,@payload_options,@header)}
  end

  test "returns decode error for invalid base64" do
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ.eyJpc3MiOiJDaHJpcyBXZXN0b24iLCJpYXQiOjE0MTA2MTc1NzQsImV4cCI6MTY5MDUwNzYzOTcsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJHaXZlbk5hbWUiOiJKb2hubnkiLCJTdXJuYW1lIjoiUm9ja2V0IiwiRW1haWwiOiJqcm9ja2V0QGV4YW1wbGUuY29tIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.llRwkrzrkAu_n4XFGvZpHR3J_p_Ow3er7LxJBZS-4M4"    
    assert_raises(JWT::VerificationError){JWT.decode(token)}
  end


end
