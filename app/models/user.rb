# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  email           :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    validates :email, :session_token, presence: true, uniqueness: true
    validates :password, length: { minimum: 6 }, allow_nil: true
    validates :password_digest, presence: {message: "Password cant be blank"}

    # again so the validation can run
    attr_reader :password

    after_initialize :ensure_session_token

    def find_by_credentials(email, password)
        user = User.find_by(email: email)
        return nil unless user && user.is_password?(password)
        return user
    end

    def password=(password)
        # the reason for this instance variable is so the validation can run
        @password = password
        BCrypt::Password.create(password)
    end

    def is_password?(password)
        # return boolean value
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end

    def reset_session_token
        self.session_token = self.class.generate_session_token
        self.save! 
        return self.session_token
        # need to return session token for our session controller
    end

    def ensure_session_token
        self.session_token ||= self.class.generate_session_token
    end

    def self.generate_session_token
        # SecureRandom seems to come with Rails
        return SecureRandom.urlsafe_base64(64)
    end


end
