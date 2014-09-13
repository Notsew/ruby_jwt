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
  	jwt = JWT.sign(@payload,@secret,@payload_options)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,@secret,@payload_options)
    assert_equal(@header,decoded.header, "header is invalid") and assert_equal(@payload,decoded.payload,"payload is invalid") and assert_equal(true,verified_jwt.success)
  end

   test "should encode and decode none" do
  	@header = {:typ => "JWT", :alg => "none"}
  	jwt = JWT.sign(@payload,nil,@payload_options,@header)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,nil,@payload_options)
    assert_equal(@header,decoded.header, "header is invalid") and assert_equal(@payload,decoded.payload,"payload is invalid") and assert_equal(true,verified_jwt.success)
  end

  test "should encode and decode RSA" do
  	@header = {:typ => "JWT", :alg => "RS384"}
  	jwt = JWT.sign(@payload,@key,@payload_options,@header)
  	decoded = JWT.decode(jwt)
  	verified_jwt = JWT.verify(jwt,@key,@payload_options)
    assert_equal(@header,decoded.header, "header is invalid") and assert_equal(@payload,decoded.payload,"payload is invalid") and assert_equal(true,verified_jwt.success)
  end

  test "decodes and verifies existing token" do
    secret = "0zWThVpyGq4QujsMHzTqNYZUbeXGB2Sa"
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJDaHJpcyBXZXN0b24iLCJpYXQiOjE0MTA2MTc1NzQsImV4cCI6MTY5MDUwNzYzOTcsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJHaXZlbk5hbWUiOiJKb2hubnkiLCJTdXJuYW1lIjoiUm9ja2V0IiwiRW1haWwiOiJqcm9ja2V0QGV4YW1wbGUuY29tIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.llRwkrzrkAu_n4XFGvZpHR3J_p_Ow3er7LxJBZS-4M4"    
    decoded = JWT.decode(token)
    verified = JWT.verify(token,secret,{:iss => "Chris Weston", :aud => ["www.example.com", "mysite.com"]})
    assert_equal(true,verified.success) and assert_equal("Chris Weston",decoded.payload[:iss]) and assert_equal(true, (decoded.payload[:Role].include? "Manager"))
  end

  test "returns false if expired" do
    @payload_options[:exp] = - 50
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    verified_jwt = JWT.verify(jwt,@secret,@payload_options)
    assert_equal(false, verified_jwt.success) and assert_equal("JWT is expired.",verified_jwt.message)
  end

  test "returns false if wrong audience" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    verified_jwt = JWT.verify(jwt,@secret,{:aud => "not_your_app"})
    assert_equal(false, verified_jwt.success) and assert_equal("JWT audience is invalid.",verified_jwt.message)
  end

  test "returns false if wrong issuer" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    verified_jwt = JWT.verify(jwt,@secret,{:iss => "not_my_app"})
    assert_equal(false, verified_jwt.success) and assert_equal("JWT issuer is invalid.",verified_jwt.message)
  end

  test "returns false if invalid signature" do
    jwt = JWT.sign(@payload,@secret,@payload_options,@header)
    verified_jwt = JWT.verify(jwt,"bad_secret")
    assert_equal(false, verified_jwt.success) and assert_equal("JWT signature is invalid.",verified_jwt.message)
  end

  test "returns sign error for no key" do
    assert_raises(JWT::SignError){jwt = JWT.sign(@payload,nil,@payload_options,@header)}
  end

  test "returns not implemented error for unsupported algorithm" do
    assert_raises(NotImplementedError){@header[:alg] = "HS422";jwt = JWT.sign(@payload,@secret,@payload_options,@header)}
  end

  test "returns decode error for invalid base64" do
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ.eyJpc3MiOiJDaHJpcyBXZXN0b24iLCJpYXQiOjE0MTA2MTc1NzQsImV4cCI6MTY5MDUwNzYzOTcsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJHaXZlbk5hbWUiOiJKb2hubnkiLCJTdXJuYW1lIjoiUm9ja2V0IiwiRW1haWwiOiJqcm9ja2V0QGV4YW1wbGUuY29tIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.llRwkrzrkAu_n4XFGvZpHR3J_p_Ow3er7LxJBZS-4M4"    
    assert_raises(JWT::DecodeError){JWT.decode(token)}
  end


end
