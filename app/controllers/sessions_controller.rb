class SessionsController < ApplicationController
    def create
        user = User.find_by_credentials(
            params[:user][:username],
            params[:user][:password]
        )

        if user.nil?
            render json: 'Credentials were wrong'
        else
            redirect_to uses_url(user)
        end
    end

    def new
    end
end