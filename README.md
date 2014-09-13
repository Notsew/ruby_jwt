ruby_jwt
========

# Installation

	gem install ruby_jwt

# Usage
	
	JWT.sign(payload,secret,payload_options,header_options)

Note that this gem uses symbols in all of the hashes, usings strings will currently break things.

Secret can either be a RSA key or shared secret for HMAC

payload_options are the current named claims in the JWT draft.

	JWT.decode(token)

This will return a DecodeResponse object, it consists of header, payload, and signature

	decoded = JWT.decode(token)
	decoded.payload

	JWT.verify(token,secret,options)

This will return a verificationResponse object, it consists of success and message.

# Currently Supported Algorithms 

RSA: RS256,RS384,RS512
HMAC: HS256,HS384,HS512
