.PHONY: all
all: test

.PHONY: test
test:

.PHONY: deb_signed
deb_signed:
	debuild

.PHONY: deb_source
deb_source:
	debuild -S

.PHONY: deb
deb:
	debuild -us -uc

.PHONY: install
install: build $(DESTDIR)
	rsync -av build/ $(DESTDIR)/

$(DESTDIR):
	mkdir -p $(DESTDIR)

.PHONY: uninstall
uninstall: build
	-find build -type f | sed -e 's/^build/$(DESTDIR)/' | xargs rm
	-find build -type d | sed -e 's/^build/$(DESTDIR)/' | awk '{ print length(), $$0 | "sort -n -r" }' | awk '{print $$2}' | xargs rmdir

.PHONY: build
build:
	mkdir -p build

	mkdir -p build/etc/profile.d

	mkdir -p build/usr/local/appscale-tools
	cp -r bin lib templates build/usr/local/appscale-tools
	cp LICENSE README build/usr/local/appscale-tools

	install -m 0644 etc/profile.d/appscale_tools.sh build/etc/profile.d/appscale_tools.sh
	install -m 0644 etc/profile.d/appscale_config.sh build/etc/profile.d/appscale_config.sh

f ?= appscaletools
.PHONY: pylint
pylint:
	PYTHONPATH=lint:$(pwd) pylint --rcfile=files/etc/pylintrc --load-plugins astng_sh $(f)
