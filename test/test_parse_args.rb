#!/usr/bin/ruby -w
# Programmer: Chris Bunch
# Test code for lib/parse_args.rb
# Right now, just testing argument parsing, not actual content of args

require 'rubygems'
require 'flexmock/test_unit'
require 'redgreen'
require 'shoulda'

USAGE = "baz"
ALL_FLAGS = ["file", "foo", "ips"]
TARFILE = "goo.tar.gz"
YAMLFILE = "ips.yaml"

class TestParseArgs < Test::Unit::TestCase
  context "test bad input" do
    setup do
      # blank out STDERR.write so that abort(msg) doesn't write msg
      # to stderr during test runs and clog up the rake results
      stderr = flexmock(STDERR)
      stderr.should_receive(:write).and_return("")

      $:.unshift File.join(File.dirname(__FILE__), "..", "lib")
      require 'parse_args'
    end

    should "throw exceptions on bad input types" do
      assert_raise(RuntimeError) { parse_args(nil) }
      assert_raise(RuntimeError) { parse_args(1) }
      assert_raise(RuntimeError) { parse_args("") }
    end
    
    should "return an empty hash on no args" do
      assert_equal({}, parse_args([]))
    end
    
    should "exit if params are present but not flags" do
      assert_raise(SystemExit) { parse_args(["foo", "boo", "goo"]) }
    end

    should "exit on invalid flags" do
      args = ["--file", TARFILE, "--baz"]
      assert_raise(SystemExit) { parse_args(args) }
    end

    should "exit if a param is present without a flag" do
      args = ["baz", "-file", TARFILE]
      assert_raise(SystemExit) { parse_args(args) }

      args = ["-file", TARFILE, "baz"]
      assert_raise(SystemExit) { parse_args(args) }
    end
  end
  
  context "test good input" do
    should "test out one flag with one param" do
      args = ["-file", TARFILE]
      assert_equal({"file" => TARFILE}, parse_args(args))
    end
  
    should "test out one flag with no param" do
      args = ["-foo"]
      assert_equal({"foo" => "NO ARG"}, parse_args(args))
    end
  
    should "test out two flags, one with a param" do
      args = ["-foo", "-file", TARFILE]
      assert_equal({"foo" => "NO ARG", "file" => TARFILE}, parse_args(args))
    end
  
    should "same as before but in a different order" do
      args = ["-file", TARFILE, "-foo"]
      assert_equal({"foo" => "NO ARG", "file" => TARFILE}, parse_args(args))
    end
    
    should "match common virtualized deployment flags" do
      args = ["-file", TARFILE, "-ips", YAMLFILE]
      assert_equal({"file" => TARFILE, "ips" => YAMLFILE}, parse_args(args))
    end  
  
    should "allow users to type in flags with two dashes as well" do
      args = ["--file", TARFILE]
      assert_equal({"file" => TARFILE}, parse_args(args))
    end
  
    should "test two dashes, no param" do
      args = ["--foo"]
      assert_equal({"foo" => "NO ARG"}, parse_args(args))
    end
  
    should "test two flags, one with a param, both with two dashes" do
      args = ["--foo", "--file", TARFILE]
      assert_equal({"foo" => "NO ARG", "file" => TARFILE}, parse_args(args))
    end
  
    should "test two flags with params, both with dashes" do
      args = ["--file", TARFILE, "--foo"]
      assert_equal({"foo" => "NO ARG", "file" => TARFILE}, parse_args(args))
    end
    
    should "match common virtualized deployment flags with two dashes" do
      args = ["--file", TARFILE, "--ips", YAMLFILE]
      assert_equal({"file" => TARFILE, "ips" => YAMLFILE}, parse_args(args))
    end 
  end 
end