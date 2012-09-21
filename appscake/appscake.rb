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

puts "\nAppsCake - Makes deploying AppScale a 'piece of cake'!\n\n"

get '/' do
  erb :index
end

post '/virtual_advanced.do' do
  if locked?
    return report_error("Server Busy", "AppsCake is currently busy deploying a cloud. Please try again later.")
  end

  status,yaml_result = validate_yaml(params[:ips])
  if !status
    return report_error("IP Configuration Error", yaml_result)
  end
  yaml = YAML.load(params[:ips])

  status,acc_result = validate_credentials(params[:user], params[:pass], params[:pass2])
  if !status
    return report_error("AppScale Administrator Account Configuration Error", acc_result)
  end

  status,ssh_result = validate_ssh_credentials(params[:keyname], params[:root_password], yaml)
  if !status
    return report_error("AppScale SSH Configuration Error", ssh_result)
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
      @timestamp = timestamp
      @pid = pid
      @html = yaml_result
      return erb :success
    rescue Exception => e
      # If something went wrong with the fork, release the lock immediately and return
      unlock
      return report_error("Unexpected Runtime Error", "Runtime error while executing appscale tools: #{e.message}")
    end
  else
    return report_error("Server Busy", "AppsCake is currently busy deploying a cloud. Please try again later.")
  end
end

get '/view_logs' do
  timestamp = params[:ts]
  if timestamp.nil? or timestamp.length == 0
    return report_error("Invalid URL Request", "No timestamp information found in the request")
  end
  @timestamp = timestamp
  erb :view_log
end

