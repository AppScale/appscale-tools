Exec {
  path => ["/usr/bin", "/usr/local/bin", "/usr/sbin", "/bin", "/sbin"],
  logoutput => "on_failure",
}

class box_cleanup {
  exec { "fix_hosts":
    command => "sed -i -e 's/127.0.1.1.*/127.0.1.1 lucid64/' /etc/hosts",
    onlyif => "grep comcast /etc/hosts",
  }

  # set the VM to be UTC
  file { "/etc/localtime":
    ensure => absent,
  }
}

class appscale_dependencies {
  exec { "apt-get update": }

  package { ["build-essential", "debhelper", "dh-make", "dupload", "fakeroot", "lintian", "gnupg", "pbuilder", "tmux",
             "ec2-ami-tools", "ec2-api-tools", "openjdk-6-jdk", "vim", "openssh-server", "git-core", "tcsh", "python-sphinx", "python-setuptools",
             "appscale-rubygems", "ruby1.8-dev"]:
    ensure => present,
    require => Exec["apt-get update"],
    before => [File["/usr/lib/jvm/java-6-openjdk/lib/security"], File["/usr/lib/jvm/java-6-openjdk/lib/cacerts"]],
  }

  file { "/usr/lib/jvm/java-6-openjdk/lib/security":
    ensure => directory,
    recurse => true,
    mode => 0775,
    owner => root,
    group => root,
  }

  file { "/usr/lib/jvm/java-6-openjdk/lib/cacerts":
    ensure => present,
    recurse => true,
    mode => 0664,
    owner => root,
    group => root,
  }

  exec { "install_pip":
    command => "easy_install pip",
    unless => "which pip",
    require => Package["python-setuptools"],
  }

  exec { "install_rubygems_json":
    command => "gem install json --no-ri --no-rdoc",
    unless => "echo \"require 'rubygems'; require 'json'\" | ruby",
    require => [Package["appscale-rubygems"], Package["ruby1.8-dev"]],
  }

  exec { "install_virtualenvwrapper":
    command => "pip install virtualenvwrapper",
    unless => "test -e /usr/local/bin/virtualenvwrapper_lazy.sh",
    require => Exec["install_pip"],
  }
}

class appscale_development {
  file { "/home/vagrant/.bashrc":
    ensure => present,
    source => "/srv/appscale/repo/appscale-tools/files/home/vagrant/.bashrc",
  }

  file { "/home/vagrant/.devscripts":
    ensure => link,
    target => "/home/vagrant/.appscale-tools/devscripts",
  }

  file { "/etc/profile.d/completion.sh":
    ensure => present,
    source => "/srv/appscale/repo/appscale-tools/etc/profile.d/completion.sh",
  }

  file { "/etc/dupload.conf":
    ensure => present,
    source => "/srv/appscale/repo/appscale-tools/files/etc/dupload.conf",
  }

  file { "/etc/pylintrc":
    ensure => present,
    source => "/srv/appscale/repo/appscale-tools/files/etc/pylintrc",
  }

  exec { "appscale_tools_venv":
    command => "bash -c 'export WORKON_HOME=/var/lib/appscale/virtualenvs; source /usr/local/bin/virtualenvwrapper.sh && mkvirtualenv appscale-tools'",
    unless => "bash -c 'export WORKON_HOME=/var/lib/appscale/virtualenvs; source /usr/local/bin/virtualenvwrapper.sh && workon appscale-tools'",
    require => Exec["install_virtualenvwrapper"],
  }

  exec { "install python requirements":
    command => "/var/lib/appscale/virtualenvs/appscale-tools/bin/pip install -r /srv/appscale/repo/appscale-tools/requirements.txt",
    require => Exec["appscale_tools_venv"],
    before => Exec["set_appscale_tools_venv_permissions"],
  }

  exec { "check install appscale-tools package":
    cwd => "/tmp",
    command => "echo hi",
    require => Exec["install python requirements"],
    before => Exec["set_appscale_tools_venv_permissions"],
    notify => Exec["install appscale-tools package"],
    unless => "/var/lib/appscale/virtualenvs/appscale-tools/bin/python -c 'from appscaletools import ec2'",
    logoutput => "on_failure",
  }

  exec { "install appscale-tools package":
    cwd => "/srv/appscale/repo/appscale-tools",
    command => "/var/lib/appscale/virtualenvs/appscale-tools/bin/python setup.py install",
    require => Exec["appscale_tools_venv"],
    before => Exec["set_appscale_tools_venv_permissions"],
    refreshonly => true,
    logoutput => "on_failure",
  }

  exec { "set_appscale_tools_venv_permissions":
    command => "chown -R vagrant.vagrant /var/lib/appscale",
    require => Exec["appscale_tools_venv"],
    logoutput => "on_failure",
  }
}

class appscale_tools {
  exec { "package_appscale_tools":
    command => "make deb",
    cwd => "/srv/appscale/repo/appscale-tools",
    unless => "test -e /srv/appscale/repo/appscale-tools*deb",
    logoutput => "on_failure",
  }

  exec { "appscale_tools_deps":
    command => "apt-get install -y $(grep '^Depends' /srv/appscale/repo/appscale-tools/debian/control | sed -e 's/.*Depends: //' -e 's/,//g')",
    require => [Exec["apt-get update"], Exec["package_appscale_tools"]],
    logoutput => "on_failure",
  }

  exec { "remove_tools_deb":
    command => "apt-get remove -y appscale-tools",
    onlyif => "dpkg -l 'appscale-tools' | grep '^i'",
  }

  exec { "install_appscale_tools":
    command => "dpkg -i $(ls -1t appscale-tools*deb | head -n1)",
    cwd => "/srv/appscale/repo",
    require => [Exec["appscale_tools_deps"], Exec["remove_tools_deb"]],
    logoutput => "on_failure",
  }
}

class appscale {
  file { "/etc/apt/sources.list.d/appscale.list":
    ensure => present,
    source => "/srv/appscale/repo/appscale-tools/files/etc/apt/sources.list.d/appscale.list",
  }

  exec { "add_appscale_key_to_apt":
    command => "curl http://apt.appscale.com/appscale_releases.pub.gpg | apt-key add -",
    unless => "sudo apt-key list | grep AppScale",
  }
}

include box_cleanup
include appscale_dependencies
include appscale_development
include appscale
include appscale_tools
