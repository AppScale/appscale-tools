# Programmer: Chris Bunch

# a generic class to represent exceptions thrown within AppScale
class AppScaleException < Exception
end

# a class representing exceptions related to bad command line arguments
# (see lib/parse_args)
class BadCommandLineArgException < AppScaleException
end

# a class representing exceptions related to incorrectly configured
# AppScale deployments
class BadConfigurationException < AppScaleException
end

# a class representing exceptions related to cloud infrastructures
# (e.g., if euca or ec2 throw errors)
class InfrastructureException < AppScaleException
end

# a class representing exceptions related to app engine apps
# to be uploaded
class AppEngineConfigException < AppScaleException
end
