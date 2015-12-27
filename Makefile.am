ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I. -I$(top_srcdir)/src -I$(top_srcdir)/compat -I$(top_builddir)/src

libmicrodns_la_SOURCES = \
	compat/compat.c compat/compat.h \
	src/mdns.c \
	src/microdns.h \
	src/rr.c src/rr.h \
	src/utils.h

lib_LTLIBRARIES = libmicrodns.la
libmicrodns_la_LDFLAGS = -export-symbols-regex '^(mdns|rr)_'
libmicrodns_la_LIBADD = $(LIBSOCKET)

EXTRA_PROGRAMS = test announce

test_SOURCES = examples/main.c
test_LDADD = libmicrodns.la
announce_SOURCES = examples/announce.c
announce_LDADD = libmicrodns.la

pkginclude_HEADERS = src/microdns.h src/rr.h
pkgconfig_DATA = src/microdns.pc

dist_doc_DATA = README.md
