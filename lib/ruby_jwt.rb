require 'base64'
require 'openssl'
require 'json'

module JWT

	class VerificationError < StandardError;end
	class SignError < StandardError;end
	class DecodeResponse
		attr_accessor :header, :payload, :signature
		def initialize(header,payload,signature)
			@header = header
			@payload = payload
			@signature = signature
		end
	end
	# class VerificationResponse
	# 	attr_accessor :success, :message, :decoded_token

	# 	def initialize(success,message, decoded = nil)
	# 		@success = success
	# 		@message = message
	# 		@decoded_token = decoded
	# 	end
	# end

	# class OpenSSL::PKey::EC
	# 	alias_method :private?, :private_key?
	# end

	SIGNATURES = {"256" => OpenSSL::Digest::SHA256.new(), "384" => OpenSSL::Digest::SHA384.new(), "512" => OpenSSL::Digest::SHA512.new()}

	module_function

	def sign(payload,key,payload_options,header_options)
		jwt_parts = []
		header_options = header_options || {}
		payload_options = payload_options || {}
		header_options[:alg] = header_options[:alg] || "HS256"
		if(header_options[:alg] != "none" and (!key))
			raise JWT::SignError.new("Key cannot be blank if algorithm is not 'none'")
		end
		payload[:iat] = Time.now.to_i
		if(payload_options[:exp])
			payload_options[:exp] += payload[:iat] 
		end

		if(payload_options[:nbf])
			payload_options[:nbf] += payload[:iat]
		end
		payload.merge!(payload_options)
		jwt_parts << encode_header(header_options)
		jwt_parts << encode_payload(payload)
		jwt_parts << encode_signature(jwt_parts.join("."),key, header_options[:alg])
		return jwt_parts.join(".")
	end

	def decode(token)
		jwt_parts = token.split(".")
		header = json_decode_data(jwt_parts[0])
		payload = json_decode_data(jwt_parts[1])
		return DecodeResponse.new(header,payload,jwt_parts[2])
	end

	def verify(token,secret,options={})
		raise VerificationError.new("JWT cannot be blank") if !token or token.empty?
		jwt_parts = token.split(".")
		jwt = decode(token)
		alg = jwt.header[:alg]
		
		raise VerificationError.new("JWT has invalid number of segments.") if(jwt_parts.count < 3 and alg != "none")
		raise VerificationError.new("JWT has invalid number of segments.") if(jwt_parts.count < 2 and alg == "none")

		payload = jwt.payload
		signature = jwt.signature.nil? ? "none" : base64urldecode(jwt.signature)

		raise VerificationError.new("JWT signature is required.") if(jwt.signature.nil? and !secret.nil?) 
		current_time = Time.now.to_i
		if(payload[:exp] and current_time >= payload[:exp])
			raise VerificationError.new("JWT is expired.")
		end

		if(payload[:nbf] and current_time < payload[:nbf])
			raise VerificationError.new( "JWT nbf has not passed yet.")
		end

		if(options[:iss])
			raise VerificationError.new("JWT issuer is invalid.") if options[:iss] != payload[:iss]
		end

		if(options[:aud])
			audience = (options[:aud].is_a? Array) ? options[:aud] : [options[:aud]]
			raise VerificationError.new("JWT audience is invalid.") if !audience.include? payload[:aud]
		end

		raise VerificationError.new("JWT signature is invalid.") if !verify_signature(alg,secret,jwt_parts[0..1].join("."),signature)

		return jwt
	end



	#utility methods

	def json_decode_data(data)
		if defined?(Rails)
			return JSON.load(base64urldecode(data)).symbolize_keys!
		else
			return symbolize_keys(JSON.load(base64urldecode(data)))
		end
	end

	def encode_header(header_options)
		header  = {:typ => "JWT"}.merge(header_options)
		return base64urlencode(JSON.dump(header))
	end

	def encode_payload(payload)
		return base64urlencode(JSON.dump(payload))
	end

	def encode_signature(data,key,alg)
		case alg
		when "none"
			return ""
		when "HS256","HS384", "HS512"
			return base64urlencode(OpenSSL::HMAC.digest(SIGNATURES[alg.gsub("HS","")], key, data))
		when "RS256", "RS384", "RS512"
			return base64urlencode(key.sign(SIGNATURES[alg.gsub("RS","")],data))
		when "ES256", "ES384", "ES512"
			return base64urlencode(key.dsa_sign_asn1(SIGNATURES[alg.gsub("ES","")].digest(data)))
			#return base64urlencode(key.sign(SIGNATURES[alg.gsub("ES","")],data))
		else
			raise JWT::SignError.new("Unsupported signing method!")
		end
	end

	def verify_signature(alg,key,data,signature)
		case alg
		when "none"
			return true
		when "HS256","HS384", "HS512"
			return time_compare(signature,OpenSSL::HMAC.digest(SIGNATURES[alg.gsub("HS","")], key, data))
		when "RS256", "RS384", "RS512"
			return key.verify(SIGNATURES[alg.gsub("RS","")],signature, data)
		when "ES256", "ES384", "ES512"
			return key.dsa_verify_asn1(SIGNATURES[alg.gsub("ES","")].digest(data),signature)
			#return key.verify(SIGNATURES[alg.gsub("ES","")],signature, data)
		else
			raise JWT::VerificationError.new("Unsupported signing method!")
		end
	end

	def base64urlencode(val)
		return Base64.urlsafe_encode64(val).gsub("=","")
	end

	def base64urldecode(val)
		begin
			case(val.length % 4)
			when 0 
				return Base64.urlsafe_decode64(val)
			when 2
				return Base64.urlsafe_decode64("#{val}==")
			when 3
				return Base64.urlsafe_decode64("#{val}=")
			else
				raise JWT::DecodeError.new("Illegal base64 string!")
			end
		rescue ArgumentError => e
			raise JWT::VerificationError.new(e.message)
		end

	end

	def symbolize_keys(hash)
		return hash.inject({}){|memo,(k,v)| memo[k.to_sym] = v; memo}
	end

	def time_compare(a,b)
	  	return false if a.nil? || b.nil? || a.empty? || b.empty? || a.bytesize != b.bytesize
	  	l = a.bytes
	    compare = 0
	  	b.bytes.each {|byte| compare += byte ^ l.shift}
		return compare == 0
  	end
end
