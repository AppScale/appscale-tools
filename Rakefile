# install pre-reqs with
# gem install shoulda
# gem install redgreen
# gem install flexmock

require "rubygems" 
require "rake"
require "rake/testtask"
require "redgreen"
require "shoulda"
require "flexmock"

task :default => [:test]

Rake::TestTask.new do |test|
  test.libs << "test" 
  test.test_files = Dir[ "test/test*.rb" ]
  test.verbose = true
end
