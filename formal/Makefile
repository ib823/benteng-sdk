FSTAR_HOME ?= /opt/fstar
KRML_HOME ?= /opt/karamel

FSTAR = $(FSTAR_HOME)/bin/fstar.exe
KRML = $(KRML_HOME)/krml

FSTAR_FLAGS = --cache_dir .cache --cache_checked_modules
KRML_FLAGS = -skip-compilation -tmpdir out

MODULES = Envelope.Spec AAD.Binding KDF.HKDF.Spec Verify.Path.Spec

.PHONY: all verify extract clean

all: verify extract

verify: $(MODULES:%=%.checked)

%.checked: %.fst
	$(FSTAR) $(FSTAR_FLAGS) $
	@touch $@

extract:
	$(KRML) $(KRML_FLAGS) $(MODULES:%=%.fst)

clean:
	rm -rf .cache *.checked out
