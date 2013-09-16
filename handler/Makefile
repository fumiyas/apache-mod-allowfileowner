CFLAGS=
APXS=		apxs -Wc,"$(CFLAGS)"

default: build

build: mod_allowfileowner.la

mod_allowfileowner.la: mod_allowfileowner.c
	$(APXS) -c mod_allowfileowner.c

install: mod_allowfileowner.la
	$(APXS) -i mod_allowfileowner.la

clean:
	$(RM) -r .libs *.la *.lo *.slo

