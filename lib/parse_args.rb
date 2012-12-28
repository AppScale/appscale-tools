#!/usr/bin/ruby
# Programmer: Chris Bunch


require 'base64'


$:.unshift File.join(File.dirname(__FILE__))
require 'common_functions'
require 'custom_exceptions'

        
NO_APP_FOUND = "The specified App Engine app didn't exist."
FILE_FLAG_NOT_VALID_MSG = "File must be either a directory or end with .tar.gz"
IPS_FLAG_NOT_A_YAML_MSG = "YAML file must end with .yaml or .yml"
MIN_FLAG_NOT_A_NUM_MSG = "Min images must be a positive integer"
MAX_FLAG_NOT_A_NUM_MSG = "Max images must be a positive integer"
TABLE_FLAG_NOT_IN_SET_MSG = "Invalid table type. Table must be set to one" +
  " of the following: #{VALID_TABLE_TYPES.join(', ')}"
MIN_FLAG_NOT_POSITIVE_MSG = "Minimum image number must be larger than zero"
MAX_FLAG_NOT_POSITIVE_MSG = "Maximum image number must be larger than zero"

MAX_SMALLER_THAN_MIN_MSG = "Maximum image number must be larger than " +
  "the minimum image number"

YAML_CONTROL_MSG = "The provided IP yaml file did not have one IP " +
  "address for the controller node"

EC2_USAGE_MSG = "You did not provide an ips.yaml file, and you" +
  " did not provide a machine id."
EC2_IPS_MISSING_MSG = "You did not provide an ips.yaml or it was empty."
POSSIBLE_INSTANCE_TYPES = ["m1.small", "m1.medium", "m1.large", "m1.xlarge", "c1.xlarge"]
INSTANCE_FLAG_NOT_IN_SET_MSG = "The instance type you provided was " +
  "not one of the allowed values. Currently we allow the " +
  "#{POSSIBLE_INSTANCE_TYPES.join(', ')} instance types."
INFRASTRUCTURE_FLAG_NOT_IN_SET_MSG = "The infrastructure you provided " + 
  "was not one of the allowed values. Currently we allow ec2 and euca " + 
  "as the infrastructure types."

DJINN_SERVER_DIED_MSG = "\nEither the head node was unable to get IP " + 
  "addresses for any slave nodes or a bug in the head node's code caused" +
  " it to crash. We have left your virtual machines running in case you " +
  "wish to submit a bug report or investigate further via " +
  "the Troubleshooting page."

RW_REQUIRES_VOLDEMORT_MSG = "The r and w flags can only be used in " +
  "conjunction with the Voldemort database. Please either specify the" +
  " Voldemort database to be used or remove the r and w flags."

BACKUP_TAR_EXISTS_MSG = "The tar file you specified to back up to " + 
  "already exists. Please specify a new file name and try again."
BACKUP_NEPTUNE_INFO_EXISTS_MSG = "The Neptune info file you specified " +
  " to back up to already exists. Please specify a new file name and try again."

RESTORE_TAR_NOT_EXISTS_MSG = "The tar file you specified to back up" + 
  " from does not exist. Please specify a new file name and try again."
RESTORE_NEPTUNE_INFO_NOT_EXISTS_MSG = "The Neptune info file you specified" +
  " does not exist. Please specify a new file name and try again."

CONFIG_FILE_NOT_FOUND = "The configuration file you specified did not exist." +
  " Please specify one that exists and try again."
NO_MIN_OR_MAX_WITH_IPS = "When using the ips flag, the min or max flags " +
  "cannot be specified. Please only use either (1) the min and max flags or " +
  "(2) the ips flag."

FILE_REGEX = /\.tar\.gz$/
POS_NUM_REGEX = /^[1-9]\d*$/
TAR_REGEX = /\.tar\.gz$/
YAML_REGEX = /\.ya?ml$/

DEFAULT_DATASTORE = "cassandra"


module ParseArgs
  public
  
  def self.get_vals_from_args(arg_list, all_flags, usage)
    val_hash = {}

    arg_hash = parse_argv(arg_list, all_flags, usage)

    if arg_hash['help'] || arg_hash['h'] || arg_hash['usage']
      raise BadCommandLineArgException.new(usage)
    end

    if arg_hash['version']
      raise BadCommandLineArgException.new(AS_VERSION)
    end

    self.get_min_and_max_images_and_ips(arg_hash, val_hash)

    if arg_hash['file']
      true_location = File.expand_path(arg_hash['file'])
      if !File.exists?(true_location)
        raise BadCommandLineArgException.new(NO_APP_FOUND)
      end

      if !((File.directory?(true_location)) or (true_location =~ TAR_REGEX))
        raise BadCommandLineArgException.new(FILE_FLAG_NOT_VALID_MSG) 
      end

      val_hash['file_location'] = arg_hash['file']
    else
      val_hash['file_location'] = nil
    end

    self.get_table_args(arg_hash, val_hash)
    self.get_cloud_args(arg_hash, val_hash)

    if arg_hash['keyname']
      val_hash['keyname'] = arg_hash['keyname']
    else
      val_hash['keyname'] = "appscale"
    end

    if arg_hash['appname']
      val_hash['appname'] = arg_hash['appname'].gsub(/[^\w\d-]/, "")
    else
      val_hash['appname'] = nil
    end

    # If the user tells us exactly how many application servers they want
    # per application, then don't use the autoscaling support.
    if arg_hash['appengine']
      val_hash['appengine'] = Integer(arg_hash['appengine'])
      val_hash['autoscale'] = false
    else
      val_hash['appengine'] = 1
      val_hash['autoscale'] = true
    end

    if arg_hash['separate']
      val_hash['separate'] = true
    else
      val_hash['separate'] = false
    end

    val_hash['confirm'] = !arg_hash['confirm'].nil?

    self.get_backup_and_restore_params(arg_hash, val_hash)
    self.get_developer_flags(arg_hash, val_hash)

    return val_hash
  end

  private
  
  def self.parse_argv(command_line, all_flags, usage)
    if command_line.class != Array
      raise BadCommandLineArgException.new("argv was not an Array, but was a #{command_line.class}")
    end

    arg_hash = {}
  
    arg_found = nil
    command_line.each { |arg|
      if arg[0].chr == "-"
        arg = arg[1, arg.length]
        arg = arg[1, arg.length] if arg[0].chr == "-" # to handle --arg
        arg_found = arg
        if !all_flags.include?(arg)
          raise BadCommandLineArgException.new("The flag #{arg} cannot be used here.")
        end
      
        arg_hash[arg] = "NO ARG"
      elsif !arg_found.nil?
        arg_hash[arg_found] = arg
        arg_found = nil
      else
        raise BadCommandLineArgException.new("The parameter #{arg} was specified without a corresponding flag.")
      end
    }
  
    return arg_hash
  end

  def self.get_min_and_max_images_and_ips(arg_hash, val_hash)
    if arg_hash['min']
      if arg_hash['min'] !~ POS_NUM_REGEX
        raise BadCommandLineArgException.new(MIN_FLAG_NOT_A_NUM_MSG)
      end

      min_images = Integer(arg_hash['min'])
    end

    if arg_hash['max']
      if arg_hash['max'] !~ POS_NUM_REGEX
        raise BadCommandLineArgException.new(MAX_FLAG_NOT_A_NUM_MSG)
      end

      max_images = Integer(arg_hash['max'])
  
      if !arg_hash['min']
        min_images = max_images
      end
    end

    if min_images and max_images and min_images > max_images
      raise BadCommandLineArgException.new(MAX_SMALLER_THAN_MIN_MSG)
    end

    val_hash['min_images'] = min_images
    val_hash['max_images'] = max_images

    if arg_hash['ips']
      # users shouldn't be allowed to specify ips and min/max
      if arg_hash['min'] or arg_hash['max']
        raise BadCommandLineArgException.new(NO_MIN_OR_MAX_WITH_IPS)
      end

      begin
        val_hash['ips'] = YAML.load_file(arg_hash['ips'])
      rescue Errno::ENOENT
        abort(CONFIG_FILE_NOT_FOUND)
      end
    else
      val_hash['ips'] = nil
    end

    if arg_hash['ips_layout']
      val_hash['ips'] = Base64.decode64(arg_hash['ips_layout'])
    end
  end

  def self.get_table_args(arg_hash, val_hash)
    if arg_hash['table']
      if !VALID_TABLE_TYPES.include?(arg_hash['table'])
        raise BadCommandLineArgException.new(TABLE_FLAG_NOT_IN_SET_MSG)
      end
      val_hash['table'] = arg_hash['table']
    else
      val_hash['table'] = DEFAULT_DATASTORE
    end

    if arg_hash['n']
      if arg_hash['n'] !~ POS_NUM_REGEX
        raise BadCommandLineArgException.new("n must be a positive integer")
      end
  
      val_hash['replication'] = Integer(arg_hash['n'])
    else
      val_hash['replication'] = nil
    end

    if val_hash['table'] != 'voldemort' and (arg_hash['r'] or arg_hash['w'])
      raise BadCommandLineArgException.new(RW_REQUIRES_VOLDEMORT_MSG)
    end

    if arg_hash['r']
      if arg_hash['r'] !~ POS_NUM_REGEX
        raise BadCommandLineArgException.new("r must be a positive integer")
      end

      val_hash['voldemort_r'] = Integer(arg_hash['r'])
    else
      val_hash['voldemort_r'] = nil
    end

    if arg_hash['w']
      if arg_hash['w'] !~ POS_NUM_REGEX
        raise BadCommandLineArgException.new("w must be a positive integer")
      end

      val_hash['voldemort_w'] = Integer(arg_hash['w'])
    else
      val_hash['voldemort_w'] = nil
    end
  end

  def self.get_cloud_args(arg_hash, val_hash)
    if arg_hash['infrastructure'] 
      infra = arg_hash['infrastructure']
      if !VALID_CLOUD_TYPES.include?(infra)
        raise BadCommandLineArgException.new(INFRASTRUCTURE_FLAG_NOT_IN_SET_MSG)
      end
      val_hash['infrastructure'] = infra
    else
      val_hash['infrastructure'] = nil
    end

    if arg_hash['machine']
      val_hash['machine'] = arg_hash['machine']
      if val_hash['machine'] == "NO ARG"
        raise BadCommandLineArgException.new("You failed to provide an argument for the #{flag} flag. Please do so and try again.")
      end
    else
      val_hash['machine'] = ENV['APPSCALE_MACHINE']
    end 

    if arg_hash['instance_type']
      if !POSSIBLE_INSTANCE_TYPES.include?(arg_hash['instance_type'])
        raise BadCommandLineArgException.new(INSTANCE_FLAG_NOT_IN_SET_MSG)
      end
      val_hash['instance_type'] = arg_hash['instance_type']
    else
      val_hash['instance_type'] = "m1.large"
    end

    if arg_hash['v'] or arg_hash['verbose']
      val_hash['verbose'] = true
    else
      val_hash['verbose'] = false
    end

    # The group flag is used to indicate the name of the security group that should
    # be used in EC2 and Eucalyptus deployments. If used in Xen and KVM deployments,
    # this flag has no effect. The security group should not exist prior to running
    # AppScale - if it does exist, the tools will abort accordingly.
    if arg_hash['group']
      val_hash['group'] = arg_hash['group']
    else
      val_hash['group'] = "appscale"
    end
  end

  def self.get_backup_and_restore_params(arg_hash, val_hash)
    if arg_hash['backup_to_tar']
      if File.exists?(arg_hash['backup_to_tar'])
        raise BadCommandLineArgException.new(BACKUP_TAR_EXISTS_MSG)
      end

      val_hash['backup_tar_location'] = arg_hash['backup_to_tar']
    else
      val_hash['backup_tar_location'] = nil
    end

    if arg_hash['backup_to_ebs']
      val_hash['backup_ebs_location'] = arg_hash['backup_to_ebs']
    else
      val_hash['backup_ebs_location'] = nil
    end

    if arg_hash['backup_neptune_info']
      if File.exists?(File.expand_path(arg_hash['backup_neptune_info']))
        raise BadCommandLineArgException.new(BACKUP_NEPTUNE_INFO_EXISTS_MSG)
      end

      val_hash['backup_neptune_info'] = File.expand_path(arg_hash['backup_neptune_info'])
    else
      val_hash['backup_neptune_info'] = nil
    end

    if arg_hash['restore_from_tar']
      unless File.exists?(arg_hash['restore_from_tar'])
        raise BadCommandLineArgException.new(RESTORE_TAR_NOT_EXISTS_MSG)
      end

      val_hash['restore_from_tar'] = arg_hash['restore_from_tar']
    else
      val_hash['restore_from_tar'] = nil
    end

    if arg_hash['restore_neptune_info']
      unless File.exists?(arg_hash['restore_neptune_info'])
        raise BadCommandLineArgException.new(RESTORE_NEPTUNE_INFO_NOT_EXISTS_MSG)
      end

      val_hash['restore_neptune_info'] = arg_hash['restore_neptune_info']
    else
      val_hash['restore_neptune_info'] = nil
    end

    if val_hash['file_location'] && (val_hash['restore_from_tar'] || val_hash['restore_from_ebs'])
      bad_restore_params = "You cannot restore an AppScale instance " + 
        "and upload a new application. Please remove one and try again."
      raise BadCommandLineArgException.new(bad_restore_params)
    end
  end

  # These flags are considered to be 'advanced use' flags, handling things that
  # may not be necessary in standard AppScale deployments. This includes the
  # functionality to rsync over an AppScale directory (scp), use 'expect' to
  # automatically inject the user's SSH password (auto), and so on.
  def self.get_developer_flags(arg_hash, val_hash)
    if arg_hash['auto']
      val_hash['auto'] = true
    else
      val_hash['auto'] = false
    end

    if arg_hash['force']
      val_hash['force'] = true
    else
      val_hash['force'] = false
    end

    if arg_hash['scp']
      if arg_hash['scp'] == 'NO ARG'
        val_hash['scp'] = "~/appscale"
      else
        val_hash['scp'] = arg_hash['scp']
      end
    else
      val_hash['scp'] = false
    end

    if arg_hash['test']
      val_hash['test'] = true
    else
      val_hash['test'] = false
    end

    if arg_hash['email']
      val_hash['email'] = arg_hash['email']
    else
      val_hash['email'] = false
    end
  end
end
