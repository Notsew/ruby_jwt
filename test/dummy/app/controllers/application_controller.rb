class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def verify_token
  	if(cookies[:session_token])
      begin
  		  x = JWT.verify(cookies[:session_token],"secret")
  		  @current_user = User.find(x.payload[:user_id])
      rescue JWT::VerificationError => e
        redirect_to root_path
      end
  	else
  		redirect_to root_path
  	end

  	

  end

end
