# Programmer: Chris Bunch

require 'common_functions'
require 'custom_exceptions'

module UsageText
  def self.get_usage(file_name, flags)
    preamble = "#{AS_VERSION}\n\nUsage: #{file_name} OPTIONS\n\nFlags:"
    flag_text = ""
    flags.each { |flag|
      if !self.respond_to?(flag.to_sym)
        raise BadCommandLineArgException.new(flag)
      end

      flag_text += "\n\t" + self.send(flag.to_sym)
    }
    return preamble + flag_text + "\n\n"
  end

  def self.appengine
    "--appengine NUM: The number of application servers that should be spawned up for each Google App Engine app."
  end

  def self.appname
    "--appname APPNAME: The name of the application to remove."
  end

  def self.auto
    "--auto: Requests the SSH login password from the user once, and then automatically reuses the password on each machine."
  end

  def self.backup_neptune_info
    "--backup_neptune_info FILE: Backs up Neptune job metadata to FILE."
  end

  def self.confirm
    "--confirm: Skips the confirmation step when removing an application."
  end

  def self.email
    "--email EMAIL: Uses EMAIL as the app administrator for the given application instead of prompting for it."
  end

  def self.file
    "--file FILE: The app to upload. Must be a directory or file tar'ed up via 'tar -czf app.tar.gz .' in the application's top level directory."
  end

  def self.force
    "--force: If the given keyname is already in use, remove it from the system and add a new key with the same name."
  end

  def self.group
    "--group: The name of the security group to create when running over a cloud infrastructure."
  end

  def self.h
    "-h: Displays this usage message."
  end

  def self.help
    "--help: Displays this usage message."
  end

  def self.instance_type
    "--instance_type: The instance type to use if using Eucalyptus. Defaults to m1.large if not provided. Supported values are m1.large, m1.xlarge, and c1.xlarge."
  end

  def self.infrastructure
    "--infrastructure INFRASTRUCTURE: The cloud infrastructure that AppScale should utilize. Acceptable values are: #{VALID_CLOUD_TYPES.join(', ')}."
  end

  def self.ips
    "--ips: The YAML file containing the IPs (and optionally, the service placement) of the machines to use."
  end

  def self.keyname
    "--keyname KEYNAME: The name of the SSH key to use for Eucalyptus. Two AppScale instances can be run concurrently in one cloud if they have unique names, and they can conflict if they have the same name."
  end

  def self.location
    "--location LOCATION: The location where logs should be copied to on the local filesystem."
  end

  def self.machine
    "--machine IMAGE_ID: The machine image to use in Amazon EC2 or Eucalyptus. Supercedes the contents of the environment variable APPSCALE_MACHINE, which is otherwise used if this flag is not present."
  end

  def self.min
    "--min NUM: The minimum number of VMs to spawn for AppScale in cloud deployments."
  end

  def self.max
    "--max NUM: The maximum number of VMs to spawn for AppScale in cloud deployments."
  end

  def self.n
    "-n NUM: The replication factor that should be used with the underlying database."
  end

  def self.r
    "-r NUM: The number of database nodes needed for a read to succeed. Not supported by all databases."
  end

  def self.restore_from_tar
    "--restore_from_tar LOCATION: The location of the tar file that can be used to back up the state of a previously running AppScale deployment."
  end

  def self.restore_neptune_info
    "--restore_neptune_info LOCATION: The location of a previously saved Neptune job metadata file, to be used when starting a new Appscale deployment."
  end

  def self.scp
    "--scp LOCATION: A location on the local file system where a copy of the AppScale main branch is located. This flag instructs the tools to rsync this branch over to all nodes used. Useful for testing and debugging. If no value is provided, ~/appscale is used."
  end

  def self.table
    "--table DATABASE: The database to use with AppScale. Acceptable values are: #{VALID_TABLE_TYPES.join(', ')} (default is #{DEFAULT_DATASTORE})."
  end

  def self.test
    "--test: Uses a default username and password when uploading an application. Intended for testing only."
  end

  def self.usage
    "--usage: Displays this usage message."
  end

  def self.v
    "-v: Displays extra output. Useful for debugging."
  end

  def self.verbose
    "--verbose: Displays extra output. Useful for debugging."
  end

  def self.version
    "--version: Displays the version of the AppScale tools used."
  end

  def self.w
    "-w NUM: The number of database nodes needed for a write to succeed. Not supported by all databases."
  end

end
