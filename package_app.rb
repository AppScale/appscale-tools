#!/usr/bin/ruby -w
# Programmer: Chris Bunch
# Takes the appscale-tools directory and packages it up for release

require 'fileutils'

relative_path = File.dirname(__FILE__)
`rm -rf ~/Desktop/appscale-tools`
FileUtils.cp_r("#{relative_path}/../appscale-tools", File.expand_path("~/Desktop"))
`chmod +x ~/Desktop/appscale-tools/bin/*.rb`
`rm -rf ~/Desktop/appscale-tools/bin/*.yaml`

appscale_tools = `ls ~/Desktop/appscale-tools/bin/*.rb`.split
appscale_tools.each { |tool|
  tool_no_extension = tool[0,tool.length-3]
  `mv #{tool} #{tool_no_extension}`
}
