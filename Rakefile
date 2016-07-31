require 'rubygems'
require 'rake'
require 'rubygems/package_task'
require 'rake/testtask'


# responds to 'rake test'
task :test do |test|
  sh 'python -m unittest discover -b -v -s test'
end


# responds to 'rake coverage'
task :coverage do |test|
  sh "rm -rf coverage"
  sh "coverage -e"
  sh "coverage run --include='*lib*' --omit='*tests*' --omit='*Python*' test/test_suite.py"
  sh "coverage report -m"
  sh "coverage html"
  sh "mv htmlcov coverage"
end


# 'rake' should run all tests
task :default => [:test]
