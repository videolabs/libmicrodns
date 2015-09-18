SUBDIRS = .

libmicrodns_la_SOURCES = mdns.c rr.c compat.c

lib_LTLIBRARIES = libmicrodns.la

noinst_PROGRAMS = test
test_SOURCES = main.c
test_LDADD = libmicrodns.la
if HAVE_WIN32
test_LDADD += -lws2_32
endif
