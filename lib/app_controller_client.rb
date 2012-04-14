#!/usr/bin/ruby -w
# Programmer: Chris Bunch

require 'openssl'
require 'soap/rpc/driver'
require 'timeout'

IP_REGEX = /\d+\.\d+\.\d+\.\d+/
FQDN_REGEX = /[\w\d\.\-]+/
IP_OR_FQDN = /#{IP_REGEX}|#{FQDN_REGEX}/

NO_TIMEOUT = -1
RETRY_ON_FAIL = true
ABORT_ON_FAIL = false

# A constant that indicates that verbose logging should be produced.
LOGS_VERBOSE = "high"


class AppControllerClient
  attr_reader :conn, :ip, :secret
  
  def initialize(ip, secret)
    @ip = ip
    @secret = secret
    
    @conn = SOAP::RPC::Driver.new("https://#{@ip}:17443")
    @conn.add_method("set_parameters", "djinn_locations", "database_credentials", "app_names", "secret")
    @conn.add_method("status", "secret")
    @conn.add_method("update", "app_names", "secret")
    @conn.add_method("done_uploading", "appname", "location", "secret")
    @conn.add_method("is_done_loading", "secret")
    @conn.add_method("is_app_running", "appname", "secret")
    @conn.add_method("stop_app", "app_name", "secret")    
    @conn.add_method("get_all_public_ips", "secret")
    @conn.add_method("kill", "secret")
    @conn.add_method("get_role_info", "secret")
  end
  
  def make_call(time, retry_on_except, want_output=true)
    refused_count = 0
    max = 10

    begin
      Timeout::timeout(time) {
        yield if block_given?
      }
    rescue Errno::ECONNREFUSED
      if refused_count > max
        if want_output
          abort("Connection with #{@ip} was refused. Is the AppController running?")
        else
          raise Exception
        end
      else
        refused_count += 1
        sleep(1)
        retry
      end
    rescue OpenSSL::SSL::SSLError, NotImplementedError, Errno::EPIPE, Timeout::Error, Errno::ECONNRESET
      retry
    rescue Exception => except
      if retry_on_except
        retry
      else
        if want_output
          abort("We saw an unexpected error of the type #{except.class} with the following message:\n#{except}.")
        else
          raise except
        end
      end
    end
  end

  def is_live?
    uri = "https://#{@ip}:17443"

    begin
      Timeout::timeout(5) {
        make_call(1, ABORT_ON_FAIL, want_output=false) { @conn.status(@secret) }
      }
      return true
    rescue Exception
      return false
    end
  end

  def get_userappserver_ip(verbose_level="low") 
    userappserver_ip, status, state, new_state = "", "", "", ""
    loop {
      status = get_status()

      new_state = status.scan(/Current State: ([\w\s\d\.,]+)\n/).flatten.to_s.chomp
      if verbose_level == LOGS_VERBOSE and new_state != state
        puts new_state
        state = new_state
      end
    
      if status == "false: bad secret"
        abort("\nWe were unable to verify your secret key with the head node specified in your locations file. Are you sure you have the correct secret key and locations file?\n\nSecret provided: [#{@secret}]\nHead node IP address: [#{@ip}]\n")
      end
        
      if status =~ /Database is at (#{IP_OR_FQDN})/ and $1 != "not-up-yet"
        userappserver_ip = $1
        break
      end
      
      sleep(10)
    }
    
    return userappserver_ip
  end

  def set_parameters(locations, creds, apps_to_start)
    result = ""
    make_call(10, ABORT_ON_FAIL) { 
      result = conn.set_parameters(locations, creds, apps_to_start, @secret)
    }  
    abort(result) if result =~ /Error:/
  end

  def status()
    return "Status of node at #{ip}:\n" + get_status()
  end

  def get_status()
    make_call(10, RETRY_ON_FAIL) { @conn.status(@secret) }
  end

  def stop_app(app_name)
    make_call(30, RETRY_ON_FAIL) { @conn.stop_app(app_name, @secret) }
  end
  
  def update(app_names)
    make_call(30, RETRY_ON_FAIL) { @conn.update(app_names, @secret) }
  end
 
  def get_all_public_ips()
    make_call(30, RETRY_ON_FAIL) { @conn.get_all_public_ips(@secret) }
  end

  def kill()
    make_call(NO_TIMEOUT, RETRY_ON_FAIL) { @conn.kill(@secret) }
  end

  def is_done_loading?()
    make_call(NO_TIMEOUT, RETRY_ON_FAIL) { @conn.is_done_loading(@secret) }
  end

  def done_uploading(appname, location)
    make_call(NO_TIMEOUT, RETRY_ON_FAIL) { 
      @conn.done_uploading(appname, location, @secret) 
    }
  end


  def app_is_running?(appname)
    make_call(NO_TIMEOUT, RETRY_ON_FAIL) { 
      @conn.is_app_running(appname, @secret) 
    }
  end


  # Asks the AppController to see what roles each node is running in AppScale.
  # The result is an Array, where each item is a Hash that contains information
  # about the given node.
  def get_role_info()
    make_call(NO_TIMEOUT, ABORT_ON_FAIL) { 
      @conn.get_role_info(@secret) 
    }
  end


end
