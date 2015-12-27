ACLOCAL_AMFLAGS = -I m4

CFLAGS = -I. -I$(top_srcdir)/src -I$(top_srcdir)/compat -I$(top_builddir)/src @CFLAGS@

libmicrodns_la_SOURCES = src/mdns.c src/rr.c compat/compat.c

lib_LTLIBRARIES = libmicrodns.la

noinst_PROGRAMS = test announce
test_SOURCES = examples/main.c
test_LDADD = libmicrodns.la
test_LDADD += @LIBSOCKET@
announce_SOURCES = examples/announce.c
announce_LDADD = libmicrodns.la
announce_LDADD += @LIBSOCKET@

pkginclude_HEADERS = src/microdns.h src/rr.h
pkgconfig_DATA = src/microdns.pc

dist_doc_DATA = README.md
