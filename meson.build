# This file is part of libmicrodns.
#
# Copyright © 2019 VideoLabs SAS
#
# Author: Mathieu Duponchelle <mathieu@centricular.com>
#
#########################################################################
# libmicrodns is released under LGPLv2.1 (or later) and is also available
# under a commercial license.
#########################################################################
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.

project('microDNS', ['c'],
  version : '0.1.0',
  meson_version : '>= 0.50.0',
  default_options : ['warning_level=2',
                     'buildtype=release',
                     'b_ndebug=if-release'])

mdns_version = meson.project_version()

ver_arr = mdns_version.split('.')

mdns_major_version = ver_arr[0]
mdns_minor_version = ver_arr[1]
mdns_micro_version = ver_arr[2]

cc = meson.get_compiler('c')

warning_flags = []

if cc.get_id() != 'msvc'
    warning_flags += ['-Wall', '-Wextra']
endif

warning_flags += [
    '-Wsign-compare',
    '-Wstrict-aliasing',
    '-Wstrict-overflow',
    '-Wformat=2',
    '-Wno-unused-parameter',
    '-pipe',
    '-Wcast-align',
    '-Wpointer-arith',
    '-Wmissing-prototypes',
    '-Wwrite-strings',
    '-Wlogical-op',
]

add_project_arguments(cc.get_supported_arguments(warning_flags), language: 'c')

cdata = configuration_data()

deps = []

host_system = host_machine.system()

if host_system == 'windows'
    deps += [cc.find_library('ws2_32')]
    deps += [cc.find_library('iphlpapi')]
endif

inet_ntop_src = '''
#ifdef _WIN32
#include <ws2tcpip.h>
#include <windows.h>
# if _WIN32_WINNT < 0x600
#  error Needs vista+
# endif
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
int main() {
  inet_ntop(AF_INET, NULL, NULL, 0);
}
'''

if cc.links(inet_ntop_src, dependencies: deps)
    cdata.set('HAVE_INET_NTOP', 1)
endif

poll_src = '''
#include <stddef.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
# if _WIN32_WINNT < 0x600
#  error Needs vista+
# endif
# if defined(_MSC_VER)
#   error
# endif
#else
#include <poll.h>
#endif
int main() {
  poll(NULL, 0, 0);
}
'''

if cc.links(poll_src, dependencies: deps)
    cdata.set('HAVE_POLL', 1)
endif

pollfd_check_prefix = '#include <sys/types.h>\n'

if cdata.get('HAVE_POLL', 0) == 1
    pollfd_check_prefix += '#include <poll.h>\n'
elif host_system == 'windows'
    pollfd_check_prefix += '#include <winsock2.h>'
endif

if cc.has_type('struct pollfd', prefix: pollfd_check_prefix)
    cdata.set('HAVE_STRUCT_POLLFD', 1)
endif

if cc.has_function('getifaddrs')
    cdata.set('HAVE_GETIFADDRS', 1)
endif

if cc.has_header('ifaddrs.h')
    cdata.set('HAVE_IFADDRS_H', 1)
endif

if cc.has_header('unistd.h')
	cdata.set('HAVE_UNISTD_H', 1)
endif

configure_file(output : 'config.h', configuration : cdata)

c_args = ['-DHAVE_CONFIG_H']

if host_system == 'windows'
    c_args += [
        '-D_UNICODE=1',
        '-DUNICODE=1',
        '-D_POSIX_C_SOURCE=200809L',
        '-D_BSD_SOURCE=1'
    ]
endif

if cc.get_id() == 'msvc'
    c_args += [
    '-D_CRT_NONSTDC_NO_DEPRECATE',
    '-D_CRT_SECURE_NO_WARNINGS',
    '-D_CRT_SECURE_NO_DEPRECATE',
]
endif

libcompat_sources = [
    'compat/compat.c',
    'compat/inet.c',
    'compat/poll.c',
]

incdirs = include_directories('include', 'compat')

libcompat = static_library('compat', libcompat_sources,
    include_directories: incdirs,
    dependencies: deps,
    c_args: c_args
)

libmicrodns_sources = [
    'src/mdns.c',
    'src/rr.c'
]

libmicrodns_headers = [
    'include/microdns/microdns.h',
    'include/microdns/rr.h',
]

install_headers(libmicrodns_headers, subdir: 'microdns')

libmicrodns = library('microdns', libmicrodns_sources,
    include_directories: incdirs,
    link_with: libcompat,
    dependencies: deps,
    c_args: c_args,
    install: true,
)

examples_kwargs = {
    'include_directories': incdirs,
    'link_with': libmicrodns,
    'c_args': c_args,
}

executable('listen', 'examples/main.c', kwargs: examples_kwargs)
executable('announce', 'examples/announce.c', kwargs: examples_kwargs)

pkg_cdata = configuration_data()

pkg_cdata.set('prefix', join_paths(get_option('prefix')))
pkg_cdata.set('exec_prefix', '${prefix}')
pkg_cdata.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkg_cdata.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))
pkg_cdata.set('VERSION', mdns_version)
pkg_cdata.set('LIBSOCKET', host_system == 'windows' ? '-lws2_32 -liphlpapi': '')

pkg_install_dir = '@0@/pkgconfig'.format(get_option('libdir'))

configure_file(
    input: 'src/microdns.pc.in',
    output: 'microdns.pc',
    configuration: pkg_cdata,
    install_dir: pkg_install_dir,
    install: true,
)

mdns_dep = declare_dependency(link_with : libmicrodns,
    include_directories : incdirs,
    dependencies: deps,
)

doc_cdata = configuration_data()

doc_cdata.set('PACKAGE_NAME', meson.project_name())
doc_cdata.set('VERSION', mdns_version)
doc_cdata.set('abs_top_srcdir', meson.current_source_dir())

configure_file(
    input: 'doc/Doxyfile.in',
    output: 'Doxyfile',
    configuration: doc_cdata
)
