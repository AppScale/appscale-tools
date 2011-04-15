require 'rubygems'
require 'flexmock/test_unit'
require 'redgreen'
require 'shoulda'

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'common_functions'
require 'yaml'

# Add fixture functionality a la Rails
class Test::Unit::TestCase
  @@fixtures = { }
  class InvalidFixtureName < Exception; end

  def self.fixtures list
    [list].flatten.each do |fixture|
      self.class_eval do
        # add a method name for this fixture type
        define_method(fixture) do |item|
          # load and cache the YAML
          @@fixtures[fixture] ||= YAML.load_file("test/fixtures/#{fixture.to_s}.yaml")
          raise InvalidFixtureName if !@@fixtures[fixture].include?(item.to_s)
          @@fixtures[fixture][item.to_s]
        end
      end
    end
  end
end

# Add an assert to check that something is false
module Test::Unit::Assertions
  def assert_false(object, message="")
    assert_equal(false, object, message)
  end
end
