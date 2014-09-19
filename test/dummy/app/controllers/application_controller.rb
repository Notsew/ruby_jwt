class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def verify_token
  	if(cookies[:session_token])
  		x = JWT.verify(cookies[:session_token],"secret")
  		redirect_to(root_path) if !x.success
  		@current_user = User.find(x.decoded_token.payload[:user_id])
  	else
  		redirect_to root_path
  	end

  	

  end

end
