ruby_jwt
========

# Installation

	gem install ruby_jwt

# Usage
To create/Sign a JWT

	JWT.sign(payload,secret,payload_options,header_options)

Note that this gem uses symbols in all of the hashes, usings strings will currently break things.
header_options and payload_options are hashes, they can be set to nil or you can pass an empty hash if not setting any options.

Secret can either be a RSA key, shared secret for HMAC, "none" for plaintext JWTs, or an ECDSA key

payload is the data you are wanted to send.

	{:name => "Chris", :role => "Admin"}

payload_options are the current named claims in the JWT draft.  These will be merged into the payload hash.
Note: :iat(issued at time) is automatically added to the payload.

	:iss => the issuer
	:aud => the audience the token is intended for
	:exp => should expire in X number of seconds.  This will be added to the :iat in the payload to give you the datetime in seconds the token will expire.
	:nbf => should not accept before X number of seconds.  This value is added to the :iat to determine when it should accept the token.
	:jti => This is a unique identifier that your application can check for to make a one time use token.
	:sub => the subject of the token.

header_options are the current typ and alg.  you can also pass in any custom fields and they will be added to the header.
	
	:alg => the algorithm to use, supported algorithms are listed below
	:typ => this will always be set to JWT
	:custom_header => you can supply custom header fields.

To decode a token:

	JWT.decode(token)

Note this will not verify the token.  This will return a DecodeResponse object, it consists of header, payload, and signature

	decoded = JWT.decode(token)
	decoded.payload # displays the payload
	decoded.payload[:name] # displays Chris
	decoded.header[:alg] # displays the algorithm used to sign the token

To verify a token:
	JWT.verify(token,secret,options)

This will return a verificationResponse object, it consists of success and message.
The options field is where you pass a hash of the audience and/or the issuer. Audience can be an array or a string, this library will verify that the audience in the token is included in the audience that you supply.  Same with the issuer, if issuer is passed in, they will be compared and if different will return false. 

	verified = JWT.verify(token,"secret",{:iss => "my_app"})
	// if the issuer is wrong it will respond with the Verification response object with success = false and message = "JWT issuer is invalid"
	// if the token has expired it will respond with a VerificationResponse object with success  = false and message = "JWT is expired."
	// if the token nbf has not passed yet, it will return false with the proper message.
	// if the token's audience is not included in the audience you pass in, this method will retun false with message of JWT audience is invalid.
	// if the token is valid success will be true.


# Currently Supported Algorithms 
Array of supported algorithms. The following algorithms are currently supported.  This will default to HS256, unless you pass {:alg => "your_choice_of_algo"} in the header options when doing JWT.sign

alg Parameter Value | Digital Signature or MAC Algorithm 
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm 
HS384 | HMAC using SHA-384 hash algorithm 
HS512 | HMAC using SHA-512 hash algorithm 
RS256 | RSA using SHA-256 hash algorithm
RS384 | RSA using SHA-384 hash algorithm
RS512 | RSA using SHA-512 hash algorithm
ES256 | ECDSA using SHA-256 hash algorithm
ES384 | ECDSA using SHA-384 hash algorithm
ES512 | ECDSA using SHA-512 hash algorithm
none | No digital signature or MAC value included