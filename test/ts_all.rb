$:.unshift File.join(File.dirname(__FILE__))

# bin tests
require 'tc_appscale_add_keypair'
require 'tc_appscale_add_nodes'
require 'tc_appscale_describe_instances'
require 'tc_appscale_remove_app'
require 'tc_appscale_reset_pwd'
require 'tc_appscale_run_instances'
require 'tc_appscale_terminate_instances'
require 'tc_appscale_upload_app'

# lib tests
require 'tc_app_controller_client'
require 'tc_common_functions'
require 'tc_encryption_helper'
require 'tc_god_interface'
require 'tc_node_layout'
require 'tc_parse_args'
require 'tc_user_app_client'
require 'tc_vm_tools'
