require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'openssl'
require 'jwt'
require 'json'

signin_key_path = File.expand_path("../app.rsa", __FILE__)
verify_key_path = File.expand_path("../app.rsa.pub",__FILE__)

signing_key = ""
verify_key = ""

File.open(signin_key_path) do |file|
  signing_key = OpenSSL::PKey.read(file)
end

File.open(verify_key_path) do |file|
  verify_key = OpenSSL::PKey.read(file)
end

set :signing_key, signing_key
set :verify_key, verify_key

# enable sessions which will be our default for storing the tokens
enable :sessions

set :session_secret, 'super secret'

helpers do

  def protected!
    return if authorized?
      halt(401, "Not Authorized")
  end

  def extract_token
    token = env["HTTP_ACCESS_TOKEN"]

    if token
      return token
    end

    token = request["access_token"]

    if token
      return token
    end

    return nil
  end

  def authorized?
    @token = extract_token
    begin
      payload, header = JWT.decode(@token, settings.verify_key, true)

      @exp = header["exp"]

      if @exp.nil?
        puts "Access token does not have exp set"
        return false
      end

      @exp = Time.at(@exp.to_i)

      if Time.now > @exp
        puts "Access token expired"
        return false
      end

      @user_id = payload["user_id"]

    rescue JWT::DecodeError => e
      return false
    end
  end
end

get '/' do
  content_type :json
  { whereIam: 'home'}.to_json
end

get '/protected' do
  protected!
  content_type :json
  { result: verify_key}.to_json
end

get '/test' do
  halt(401, "Not Authorized")
end

post '/login' do
  content_type :json
  credential = JSON.parse(request.body.read)
  if credential["username"] == "username" && credential["password"] == "password"

    headers = {
      exp: Time.now.to_i + 3600
    }

    @token = JWT.encode({user_id: 123456}, settings.signing_key, "RS256", headers)

    return { token: @token }.to_json
  end

  { errors: "Invalid username or password"}.to_json
end
