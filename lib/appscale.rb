#!/usr/bin/env ruby
# Programmer: Chris Bunch


$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'appscale_tools'


# AppScale is a wrapper around the AppScale Tools that uses configuration
# files to avoid making users remember the (often numerous) flags needed
# for the AppScale Tools. It is inspired by vagrant, and many of the
# directives are named after those that vagrant provides.
module AppScale


  # A list of the directives that can be used with the 'appscale'
  # command.
  DIRECTIVES = %w{init up deploy destroy}
  

  # This method examines the arguments passed to it to determine which
  # function the user wants to run. It is assumed to be the first
  # argument.
  # Args:
  #   args: The list of arguments passed to 'appscale', presumed to be
  #     an Array of Strings.
  # Raises:
  #   AppScaleException: If the function the user wants to run is not
  #     a function we can run.
  def self.get_directive(args)
    directive = args[0]
    if DIRECTIVES.include?(directive)
      return directive
    else
      raise AppScaleException.new("The directive you specified, " +
        "#{directive}, is not supported. Supported directives are: " +
        "#{DIRECTIVES.join(', ')}.")
    end
  end


end
