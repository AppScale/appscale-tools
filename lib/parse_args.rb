#!/usr/bin/ruby
# Programmer: Chris Bunch

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
INSTANCE_FLAG_NOT_IN_SET_MSG = "The instance type you provided was not " + 
  "one of the allowed values. Currently we allow m1.large, m1.xlarge, " +
  "and c1.xlarge as the instance types."
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

FILE_REGEX = /\.tar\.gz$/
POS_NUM_REGEX = /^[1-9]\d*$/
TAR_REGEX = /\.tar\.gz$/
YAML_REGEX = /\.ya?ml$/

def parse_args(command_line)
  raise if command_line.class != Array
  
  arg_hash = {}
  
  arg_found = nil
  command_line.each { |arg|
    if arg[0].chr == "-"
      arg = arg[1, arg.length]
      arg = arg[1, arg.length] if arg[0].chr == "-" # to handle --arg
      arg_found = arg
      if !ALL_FLAGS.include?(arg)
        abort "The flag #{arg} cannot be used here.\n\n#{USAGE}"
      end
      
      arg_hash[arg] = "NO ARG"
    elsif !arg_found.nil?
      arg_hash[arg_found] = arg
      arg_found = nil
    else
      abort "The parameter #{arg} was specified without a corresponding flag."
    end
  }
  
  return arg_hash
end

arg_hash = parse_args(ARGV)

flags = arg_hash.keys
flags.each { |flag|
  unless ALL_FLAGS.include?(flag)
    message = "Flag #{flag} not recognized.\n\n" + USAGE
    abort(message)
  end
}

if arg_hash['help'] || arg_hash['h'] || arg_hash['usage']
  abort(USAGE)
end

if arg_hash['version']
  abort(AS_VERSION)
end

if arg_hash['min']
  abort(MIN_FLAG_NOT_A_NUM_MSG) if arg_hash['min'] !~ POS_NUM_REGEX
  min_images = Integer(arg_hash['min'])
  if min_images < 1
    abort("--min needs to be at least one")
  end
else
  #min_images = 4
end

if arg_hash['max']
  abort(MAX_FLAG_NOT_A_NUM_MSG) if arg_hash['max'] !~ POS_NUM_REGEX
  max_images = Integer(arg_hash['max'])
  
  unless arg_hash['min']
    min_images = max_images
  end
else
  #max_images = min_images
end

#if min_images > max_images
#  abort(MAX_SMALLER_THAN_MIN_MSG)
#end

if arg_hash['file']
  true_location = File.expand_path(arg_hash['file'])
  file_doesnt_exist = "The specified AppEngine program, #{arg_hash['file']}," + 
    " didn't exist. Please specify one that exists and try again"
  abort(file_doesnt_exist) unless File.exists?(true_location)

  if not ((File.directory?(true_location)) or (true_location =~ TAR_REGEX))
    abort(FILE_FLAG_NOT_VALID_MSG) 
  end
  FILE_LOCATION = arg_hash['file']
else
  FILE_LOCATION = nil
end

if arg_hash['table']
  abort(TABLE_FLAG_NOT_IN_SET_MSG) unless VALID_TABLE_TYPES.include?(arg_hash['table'])
  TABLE = arg_hash['table']
else
  TABLE = "cassandra"
end

if arg_hash['infrastructure']
  abort(INFRASTRUCTURE_FLAG_NOT_IN_SET_MSG) unless VALID_CLOUD_TYPES.include?(arg_hash['infrastructure'])
  INFRASTRUCTURE = arg_hash['infrastructure']
else
  INFRASTRUCTURE = nil
end

if arg_hash['ips']
  begin
    IPS = YAML.load_file(arg_hash['ips'])
  rescue Errno::ENOENT
    ips_doesnt_exist = "The configuration file you specified, " + 
      "#{arg_hash['ips']}, did not exist. Please specify one that" + 
      " exists and try again."
    abort(ips_doesnt_exist)
  end
else
  IPS = nil
end

if arg_hash['n']
  abort("n must be a positive integer") if arg_hash['n'] !~ POS_NUM_REGEX
  
  REPLICATION = Integer(arg_hash['n'])
else
  REPLICATION = nil
end

if arg_hash['r']
  abort(RW_REQUIRES_VOLDEMORT_MSG) if TABLE != "voldemort"
  
  VOLDEMORT_R = Integer(arg_hash['r'])
else
  VOLDEMORT_R = nil
end

if arg_hash['w']
  abort(RW_REQUIRES_VOLDEMORT_MSG) if TABLE != "voldemort"
  
  VOLDEMORT_W = Integer(arg_hash['w'])
else
  VOLDEMORT_W = nil
end

MIN_IMAGES = min_images
MAX_IMAGES = max_images

if arg_hash['machine']
  MACHINE = arg_hash['machine']
  if MACHINE == "NO ARG"
    abort("You failed to provide an argument for the #{flag} flag. Please do so and try again.")
  end
else
  MACHINE = ENV['APPSCALE_MACHINE']
end 

possible_instance_types = ["m1.large", "m1.xlarge", "c1.xlarge"]
if arg_hash['instance_type']
  abort(INSTANCE_FLAG_NOT_IN_SET_MSG) unless possible_instance_types.include?(arg_hash['instance_type'])
  INSTANCE_TYPE = arg_hash['instance_type']
else
  INSTANCE_TYPE = "m1.large"
end

if arg_hash['v'] or arg_hash['verbose']
  @@verbose = true
else
  @@verbose = false
end

if arg_hash['scp']
  SCP = true
else
  SCP = false
end

if arg_hash['test']
  TEST = true
else
  TEST = false
end

if arg_hash['keyname']
  KEYNAME = arg_hash['keyname']
else
  KEYNAME = "appscale"
end

if arg_hash['auto']
  AUTO = true
else
  AUTO = false
end

if arg_hash['appname']
  APPNAME = arg_hash['appname'].gsub(/[^\w\d-]/, "")
else
  APPNAME = nil
end

if arg_hash['appengine']
  APPENGINE = Integer(arg_hash['appengine'])
else
  APPENGINE = 3
end

if arg_hash['force']
  FORCE = true
else
  FORCE = false
end

if arg_hash['separate']
  SEPARATE = true
else
  SEPARATE = false
end

if arg_hash['email']
  EMAIL = arg_hash['email']
else
  EMAIL = false
end

CONFIRM = !arg_hash['confirm'].nil?

if arg_hash['backup_to_tar']
  if File.exists?(arg_hash['backup_to_tar'])
    abort(BACKUP_TAR_EXISTS_MSG)
  end

  BACKUP_TAR_LOCATION = arg_hash['backup_to_tar']
else
  BACKUP_TAR_LOCATION = nil
end

if arg_hash['backup_to_ebs']
  BACKUP_EBS_LOCATION = arg_hash['backup_to_ebs']
else
  BACKUP_EBS_LOCATION = nil
end

if arg_hash['backup_neptune_info']
  if File.exists?(File.expand_path(arg_hash['backup_neptune_info']))
    abort(BACKUP_NEPTUNE_INFO_EXISTS_MSG)
  end

  BACKUP_NEPTUNE_INFO = File.expand_path(arg_hash['backup_neptune_info'])
else
  BACKUP_NEPTUNE_INFO = nil
end

if arg_hash['restore_from_tar']
  unless File.exists?(arg_hash['restore_from_tar'])
    abort(RESTORE_TAR_NOT_EXISTS_MSG)
  end

  RESTORE_FROM_TAR = arg_hash['restore_from_tar']
else
  RESTORE_FROM_TAR = nil
end

if arg_hash['restore_from_ebs']
  RESTORE_FROM_EBS = arg_hash['restore_from_ebs']
else
  RESTORE_FROM_EBS = nil
end


if arg_hash['restore_neptune_info']
  unless File.exists?(arg_hash['restore_neptune_info'])
    abort(RESTORE_NEPTUNE_INFO_NOT_EXISTS_MSG)
  end

  RESTORE_NEPTUNE_INFO = arg_hash['restore_neptune_info']
else
  RESTORE_NEPTUNE_INFO = nil
end

if FILE_LOCATION && (RESTORE_FROM_TAR || RESTORE_FROM_EBS)
  bad_restore_params = "You cannot restore an AppScale instance " + 
    "and upload a new application. Please remove one and try again."
  abort(bad_restore_params)
end
