include iatrepair/Module.mk

#
# Distribution build rules
#

zipdir          := $(BUILDDIR)/zip

$(zipdir)/:
	$(V)mkdir -p $@

$(BUILDDIR)/iatrepair.zip: \
		build/bin/indep-32/iatrepair.exe \

	$(V)echo ... $@
	$(V)zip -j $@ $^

all: $(BUILDDIR)/iatrepair.zip
