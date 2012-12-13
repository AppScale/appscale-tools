require 'rubygems'
require 'rake'
require 'rake/gempackagetask'
require 'rake/testtask'


# TODO(cgb): This probably should be moved into a Gemfile and out of this file.
# I'm just not sure how to do this right now.
spec = Gem::Specification.new do |s|
  s.name = 'appscale-tools'
  s.version = '1.6.3'

  s.summary = "A toolkit for running the AppScale cloud platform"  
  s.description = <<-EOF
    AppScale is a cloud platform that automatically configures and deploys
    applications over cloud infrastructures (Amazon EC2, Microsoft Azure),
    as well as cloud platforms (Google App Engine). It runs Google App
    Engine applications as well as arbitrary programs via the Neptune
    domain specific language.
  EOF

  s.author = "Chris Bunch"
  s.email = "appscale_community@googlegroups.com"
  s.homepage = "http://appscale.cs.ucsb.edu"

  # Anything in bin is an executable - strip off the preceding bin/
  # and take just the remainder
  executables_with_bin = Dir.glob("{bin}/**/*")
  executables = executables_with_bin.map { |e|
    e.match(/\/(.*)/)[1]
  }
  s.executables = executables

  s.platform = Gem::Platform::RUBY

  candidates = Dir.glob("{bin,doc,lib,test,samples}/**/*")
  s.files = candidates.delete_if do |item|
    item.include?(".git") || item.include?("rdoc")
  end
  s.require_path = "lib"
  s.autorequire = "appscale_tools"

  s.has_rdoc = true
  s.extra_rdoc_files = ["README", "LICENSE"]

  # We test via flexmock and run tests via rake, so make sure those are 
  # installed.
  s.add_development_dependency('flexmock')
  s.add_development_dependency('rake')
end


# responds to 'rake gem'
Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end


# responds to 'rake test'
task :test do |test|
  sh "ruby test/ts_all.rb"
  sh "PYTHONPATH='lib' python test/test_suite.py"
end


# 'rake' should run all tests
task :default => [:test]
