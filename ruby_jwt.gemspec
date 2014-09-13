$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "ruby_jwt/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "ruby_jwt"
  s.version     = RubyJwt::VERSION
  s.authors     = ["Chris Weston"]
  s.email       = ["notsew66@yahoo.com"]
  s.summary     = "JSON Web Token library for Ruby"
  s.description = "JSON Web Token library for Ruby"
  s.license     = "MIT"
  s.homepage    = "https://github.com/Notsew/ruby_jwt"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.rdoc"]
  s.test_files = Dir["test/**/*"]

  # s.add_dependency "json"
  # s.add_dependency "base64"
  # s.add_dependency "openssl"
  s.add_development_dependency "rails", "~> 4.1.5"

  s.add_development_dependency "sqlite3"
end
