#!/usr/bin/ruby
# Author: Hiranya Jayathilaka (hiranya@cs.ucsb.edu)
# AppsCake web interface for deploying and launching AppScale clouds
# AppsCake = Makes deploying AppScale a 'piece of cake'

require 'rubygems'
require 'sinatra'
require 'yaml'
require 'open3'

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscake_utils'
require 'appscale_tools'

puts "AppsCake - Makes deploying AppScale a 'piece of cake'!"

get '/' do
  erb :index
end

post '/virtual_advanced.do' do
  if locked?
    return "AppsCake is currently busy deploying a cloud. Please try again later."
  end

  status,yaml_result = validate_yaml(params[:ips])
  if !status
    return yaml_result
  end
  yaml = YAML.load(params[:ips])

  status,acc_result = validate_credentials(params[:user], params[:pass], params[:pass2])
  if !status
    return acc_result
  end

  status,ssh_result = validate_ssh_credentials(params[:keyname], params[:root_password], yaml)
  if !status
    return ssh_result
  end

  add_key_options = {
    'ips' => yaml,
    'keyname' => params[:keyname],
    'auto' => true,
    'root_password' => params[:root_password]
  }

  app_namme = nil
  file_location = nil
  if params[:target_app] != '_none_'
    app_name = params[:target_app]
    file_location = File.join(File.dirname(__FILE__), "repository", params[:target_app])
  end

  run_instances_options = { 
    'ips' => yaml, 
    'keyname' => params[:keyname],
    'file_location' => file_location,
    'appname' => app_name,
    'appengine' => 1,
    'autoscale' => true,
    'separate' => false,
    'confirm' => false,
    'table' => 'cassandra',
    'infrastructure' => nil,
    'admin_user' => params[:user],
    'admin_pass' => params[:pass]
  }

  if lock
    begin
      timestamp = Time.now.to_i
      pid = fork do
        begin
          stfu(timestamp) do
            key_file = File.expand_path("~/.appscale/#{params[:keyname]}")
            if File.exists?(key_file)
              puts "AppScale key '#{params[:keyname]}' found on the disk. Reusing..."
            else
              puts "AppScale key '#{params[:keyname]}' not found on the disk. Generating..."
              #add_key(add_key_options)
              AppScaleTools.add_keypair(add_key_options)
            end
            #deploy(run_instances_options)
            AppScaleTools.run_instances(run_instances_options)
          end
        ensure
          # If the fork was successful, the subprocess should release the lock
          unlock
        end
      end
      final_result = "<p>Your AppScale cloud is being deployed...</p>"
      final_result += "<p>Your deployment timestamp: #{timestamp}"
      final_result += "<p>Your deployment process ID: #{pid}"
      final_result += "<p>You can check the progress of the deployment at <a href=\"logs/deploy-#{timestamp}.log\">deploy-#{timestamp}.log</a></p>"
      final_result += yaml_result
      return final_result
    rescue
      # If something went wrong with the fork, release the lock immediately and return
      unlock
      return "<p>Runtime error while executing appscale tools</p>"
    end
  else
    return "<p>System is currently busy deploying another cloud. Please try again later.</p>"
  end
end
