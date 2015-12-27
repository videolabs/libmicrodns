ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I. -I$(top_srcdir)/src -I$(top_srcdir)/compat -I$(top_builddir)/src

libmicrodns_la_SOURCES = src/mdns.c src/rr.c compat/compat.c

lib_LTLIBRARIES = libmicrodns.la
libmicrodns_la_LDFLAGS = -export-symbols-regex '^(mdns|rr)_'

EXTRA_PROGRAMS = test announce

test_SOURCES = examples/main.c
test_LDADD = libmicrodns.la $(LIBSOCKET)
announce_SOURCES = examples/announce.c
announce_LDADD = libmicrodns.la $(LIBSOCKET)

pkginclude_HEADERS = src/microdns.h src/rr.h
pkgconfig_DATA = src/microdns.pc

dist_doc_DATA = README.md
