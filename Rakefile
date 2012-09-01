# install pre-reqs with
# gem install flexmock

require "rubygems" 
require "rake"
require "rake/testtask"
require "flexmock"

task :default => [:test]

Rake::TestTask.new do |test|
  test.libs << "test" 
  test.test_files = Dir[ "test/tc*.rb" ]
  test.verbose = true
end
