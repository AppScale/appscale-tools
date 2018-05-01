#!/bin/bash

#
# Script to bump the version of appscale-tools
# In general, this should be done in lockstep with the appscale repo.
#
if [ ! -e setup.py ]; then
	echo "Unable to locate the setup.py file, is your working directory the top level of the repo?"
	exit 1
fi

#
# Get the version from the setup.py file
#
version=$(grep "version=" setup.py | awk -F= '{print $2}' | tr -d "[,']")

case $1 in
	"major")
	bump_field="\$1"
	fmt_str="%s.0.0"
	;;
	"minor")
	bump_field="\$2"
	fmt_str="%s.%s.0"
	;;
	"patch")
	bump_field="\$3"
        fmt_str="%s.%s.%s"
	;;
	*)
	echo "usage: $0 [major|minor|patch]"
	exit 1
esac

new_version=$(echo $version | awk -F. "{${bump_field}++;printf \"${fmt_str}\", \$1, \$2, \$3}")
echo "Bumping version from ${version} to ${new_version}, changes not automatically commited"

# Do the changes
sed -i "/version/{s/${version}/${new_version}/}" setup.py
sed -i "/APPSCALE_VERSION/{s/${version}/${new_version}/}" appscale/tools/local_state.py
