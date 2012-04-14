# Programmer: Navraj Chohan
require 'net/http'
require 'uri'
REMOTE_URL = "http://heart-beat.appspot.com/sign2"

module RemoteLogging
  def self.remote_post(nnodes, db, infras, state, success)
    params = {"key" => "appscale",
              "infras" => infras,
              "num_nodes" => nnodes.to_s(),
              "state" => state,
              "success" => success,
              "db" => db}        
    post(params)
  end
  def self.post(params)
    uri = URI.parse(REMOTE_URL)
    response = Net::HTTP.post_form(uri, params)
    return response.body
  end
end
