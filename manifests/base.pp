Exec { path => ["/usr/bin", "/usr/local/bin", "/bin"] }

class box_cleanup {
  exec { "fix_hosts":
    command => "sed -i -e 's/127.0.1.1.*/127.0.1.1 lucid64/' /etc/hosts",
    onlyif => "grep comcast /etc/hosts",
  }

  file { "/home/vagrant/appscale":
    ensure => directory,
    mode => 0755,
    owner => vagrant,
    group => vagrant,
  }
}

class appscale_dependencies {
  exec { "apt-get update": }

  package { ["build-essential", "debhelper", "dh-make", "fakeroot", "lintian", "gnupg", "pbuilder",
             "openjdk-6-jdk", "vim", "openssh-server", "git-core", "tcsh"]:
    ensure => present,
    require => Exec["apt-get update"],
  }
}

include box_cleanup
include appscale_dependencies
