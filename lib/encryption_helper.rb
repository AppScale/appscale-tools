#!/usr/bin/ruby -w
# Programmer: Chris Bunch

require 'fileutils'
require 'openssl'
$:.unshift File.join(File.dirname(__FILE__), ".", "lib")
require 'common_functions'

module EncryptionHelper
  def self.generate_secret_key(keyname="appscale")
    path="~/.appscale/#{keyname}.secret"
    secret_key = ""
    possible = "0123456789abcdefghijklmnopqrstuvxwyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    possibleLength = possible.length
    
    32.times { |index|
      secret_key << possible[rand(possibleLength)]
    }
    
    full_path = File.expand_path(path)
    File.open(full_path, "w") { |file|
      file.puts(secret_key)
    }
    
    return secret_key, path
  end
  
  def self.generate_ssh_key(verbose, outputLocation, name, infrastructure, force)
    ec2_output = ""
    loop {
      sleep(10)  # to avoid euca replay error message
      ec2_output = CommonFunctions.shell("#{infrastructure}-add-keypair #{name} 2>&1")
      break if ec2_output.include?("BEGIN RSA PRIVATE KEY")
      if force
        puts "Trying again. Saw this from #{infrastructure}-add-keypair: #{ec2_output}" if verbose
        sleep(10)
        delete_output = CommonFunctions.shell("#{infrastructure}-delete-keypair #{name} 2>&1")
        puts "Saw this from #{infrastructure}-delete-keypair: #{delete_output}" if verbose
      else
        abort("The keyname you chose is already in the system. Please either run this tool again with the --force flag or run the following:\n#{infrastructure}-delete-keypair #{name}")
      end
    }
    
    # output is the ssh private key prepended with info we don't need
    # delimited by the first \n, so rip it off first to get just the key
    
    #first_newline = ec2_output.index("\n")
    #ssh_private_key = ec2_output[first_newline+1, ec2_output.length-1]

    if outputLocation.class == String
      outputLocation = [outputLocation]
    end
    
    outputLocation.each { |path|
      fullPath = File.expand_path(path)
      File.open(fullPath, "w") { |file|
        file.puts(ec2_output)
      }
      FileUtils.chmod(0600, fullPath) # else ssh won't use the key
    }
    
    return
  end
  
  def self.generate_pem_files(keyname)
    key_loc = File.expand_path("~/.appscale/#{keyname}-key.pem")
    cert_loc = File.expand_path("~/.appscale/#{keyname}-cert.pem")
    
    key = OpenSSL::PKey::RSA.generate(2048)
    pub = key.public_key
    ca = OpenSSL::X509::Name.parse("/C=US/ST=Foo/L=Bar/O=AppScale/OU=User/CN=appscale.cs.ucsb.edu/emailAddress=test@test.com")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = Time.now.to_i
    cert.subject = ca
    cert.issuer = ca
    cert.public_key = pub
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA1.new)
    
    File.open(key_loc, "w") { |f| f.write key.to_pem }
    File.open(cert_loc, "w") { |f| f.write cert.to_pem }
    return key_loc, cert_loc
  end
end
