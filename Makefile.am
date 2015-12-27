SUBDIRS = .

libmicrodns_la_SOURCES = mdns.c rr.c compat.c

lib_LTLIBRARIES = libmicrodns.la

noinst_PROGRAMS = test announce
test_SOURCES = main.c
test_LDADD = libmicrodns.la
test_LDADD += @LIBSOCKET@
announce_SOURCES = announce.c
announce_LDADD = libmicrodns.la
announce_LDADD += @LIBSOCKET@

pkginclude_HEADERS = microdns.h rr.h
pkgconfig_DATA = microdns.pc

dist_doc_DATA = README.md
