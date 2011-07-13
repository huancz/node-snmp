PREFIX=/usr/lib/nodejs
D=$(DESTDIR)/$(PREFIX)

S=$(shell pwd)

build:
	node-waf configure
	node-waf build

clean:
	rm -rf ./build

install:
	install -d $(D)/snmp
	cp build/default/snmp_binding.node $(D)/snmp
	strip --strip-all $(D)/snmp/snmp_binding.node
	cp package.json $(D)/snmp
	cp snmp.js $(D)/snmp

.PHONY: build clean install
