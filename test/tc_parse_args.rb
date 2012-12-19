$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'parse_args'

require 'test/unit'


class TestParseArgs < Test::Unit::TestCase
  def setup
    @args = {}
    @usage = "boo"
  end

  def get_exception_msg
    if !block_given?
      abort('need to give me a block!')
    end

    begin
      yield
    rescue SystemExit => e
      return e.message
    end
  end

  def test_flags_that_cause_program_abort
    # Using a flag that isn't acceptable should cause ParseArgs to abort
    args_1 = ['--boo!']
    all_flags_1 = []
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    # The --usage flag should cause ParseArgs to abort and print the usage
    args_2 = ['--usage']
    all_flags_2 = ['usage']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    }

    # The --version flag should cause ParseArgs to abort and print the version
    args_3 = ['--version']
    all_flags_3 = ['version']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    }
  end

  def test_get_min_and_max
    # Setting min or max below 1 is not acceptable
    args_1 = ['--min', '0']
    all_flags_1 = ['min']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    args_2 = ['--max', '0']
    all_flags_2 = ['max']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    }

    # If max is specified but not min, min should be equal to max
    args_3 = ['--max', '1']
    all_flags_3 = ['max']
    actual_3 = ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    assert_equal(actual_3['min_images'], actual_3['max_images'])

    # If max is less than min, it should abort
    args_4 = ['--min', '10', '--max', '1']
    all_flags_4 = ['min', 'max']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_4, all_flags_4, @usage)
    }
  end

  def test_table_flags
    # Specifying a table that isn't accepted should abort
    args_1 = ['--table', 'non-existant-table']
    all_flags_1 = ['table']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    # Specifying a table that is accepted should return that in the result
    args_2 = ['--table', 'cassandra']
    all_flags_2 = ['table']
    expected_2 = Hash[*args_2]
    actual_2 = ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    assert_equal('cassandra', actual_2['table'])

    # Failing to specify a table should default to a predefined table
    args_3 = []
    all_flags_3 = ['table']
    expected_3 = {}
    actual_3 = ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    assert_equal(DEFAULT_DATASTORE, actual_3['table'])

    # Specifying r or w when Voldemort isn't used should abort
    args_4 = ['--table', 'cassandra', '-r', '1']
    all_flags_4 = ['table', 'r', 'w']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_4, all_flags_4, @usage)
    }

    args_5 = ['--table', 'cassandra', '-w', '1']
    all_flags_5 = ['table', 'r', 'w']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_5, all_flags_5, @usage)
    }

    # Specifying a non-positive integer for r or w with Voldemort should abort
    args_6 = ['--table', 'voldemort', '-r', 'boo']
    all_flags_6 = ['table', 'r', 'w']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_6, all_flags_6, @usage)
    }

    args_7 = ['--table', 'voldemort', '-w', '0']
    all_flags_7 = ['table', 'r', 'w']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_7, all_flags_7, @usage)
    }

    # Specifying a non-positive integer for n should abort
    args_8 = ['--table', 'cassandra', '-n', '0']
    all_flags_8 = ['table', 'n']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_8, all_flags_8, @usage)
    }

    # Specifying a positive integer for n should be ok
    args_9 = ['--table', 'cassandra', '-n', '2']
    all_flags_9 = ['table', 'n']
    expected_9 = Hash[*args_9]
    actual_9 = ParseArgs.get_vals_from_args(args_9, all_flags_9, @usage)
    assert_equal(2, actual_9['replication'])

    # Specifying a positive integer for r or w with Voldemort should be ok
    # These tests are disabled right now since Voldemort is no longer a
    # supported datastore.
    # TODO(cgb): Remove these if we decide we're not going to support
    # Voldemort in the future, or remove this TODO if we do support
    # Voldemort again.
    #args_10 = ['--table', 'voldemort', '-r', '3']
    #all_flags_10 = ['table', 'r', 'w']
    #actual_10 = ParseArgs.get_vals_from_args(args_10, all_flags_10, @usage)
    #assert_equal(3, actual_10['voldemort_r'])

    #args_11 = ['--table', 'voldemort', '-w', '3']
    #all_flags_11 = ['table', 'r', 'w']
    #actual_11 = ParseArgs.get_vals_from_args(args_11, all_flags_11, @usage)
    #assert_equal(3, actual_11['voldemort_w'])
  end

  def test_developer_flags
    # Specifying auto, force, or test should have that carried over
    # to in the resulting hash
    ['auto', 'force', 'test'].each { |param|
      args = ["--#{param}"]
      all_flags = [param]
      actual = ParseArgs.get_vals_from_args(args, all_flags, @usage)
      assert_equal(true, actual[param])
    }
  end

  def test_infrastructure_flags
    # Specifying infastructure as EC2 or Eucalyptus is acceptable.
    args_1 = ['--infrastructure', 'ec2']
    all_flags_1 = ['infrastructure']
    actual_1 = ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    assert_equal('ec2', actual_1['infrastructure'])

    args_2 = ['--infrastructure', 'euca']
    all_flags_2 = ['infrastructure']
    actual_2 = ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    assert_equal('euca', actual_2['infrastructure'])

    # Specifying something else as the infrastructure is not acceptable.
    args_3 = ['--infrastructure', 'boocloud']
    all_flags_3 = ['infrastructure']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_3, all_flags_3, @usage)
    }

    # Specifying infrastructure via --iaas is not acceptable.
    args_4 = ['--iaas']
    all_flags_4 = AppScaleTools::RUN_INSTANCES_FLAGS
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_4, all_flags_4, @usage)
    }
  end

  def test_instance_types
    # Specifying m1.large as the instance type is acceptable.
    args_1 = ['--instance_type', 'm1.large']
    all_flags_1 = ['instance_type']
    assert_nothing_raised(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_1, all_flags_1, @usage)
    }

    # Specifying blarg1.humongous as the instance type is not
    # acceptable.
    args_2 = ['--instance_type', 'blarg1.humongous']
    all_flags_2 = ['instance_type']
    assert_raises(BadCommandLineArgException) {
      ParseArgs.get_vals_from_args(args_2, all_flags_2, @usage)
    }
  end

end
