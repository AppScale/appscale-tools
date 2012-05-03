# Programmer: Navraj Chohan


# Imports within Ruby's standard libraries
require 'net/http'
require 'uri'


# RemoteLogging provides callers with a mechanism by which they can save
# information about when the AppScale tools are successfully used. Callers
# should use these methods to indicate when AppScale has failed to start,
# and possibly any information that can be used to debug the problem.
module RemoteLogging


  # The location where the Google App Engine application runs that stores
  # profiling information about how often the AppScale tools run successfully.
  REMOTE_URL = "http://heart-beat.appspot.com/sign2"


  # Provides a convenient interface to self.post that callers can use to
  # save profiling information about running the AppScale tools.
  def self.remote_post(num_nodes, database, infrastructure, state, success)
    params = {"key" => "appscale",
              "infras" => infrastructure,
              "num_nodes" => "#{num_nodes}",
              "state" => state,
              "success" => success,
              "db" => database}
    self.post(params)
  end


  # Posts a Hash of parameters to the Google App Engine application that
  # keeps statistics about when AppScale was started successfully or failed.
  def self.post(params)
    begin
      uri = URI.parse(REMOTE_URL)
      response = Net::HTTP.post_form(uri, params)
      return response.body
    rescue Exception  # e.g., if the app is unresponsive
    end
  end


end
