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

project('microdns', ['c'],
  version : '0.2.0',
  meson_version : '>= 0.50.0',
  default_options : ['warning_level=2',
                     'buildtype=release',
                     'b_ndebug=if-release'])

mdns_version = meson.project_version()
mdns_soname_version = '1.0.0'

ver_arr = mdns_soname_version.split('.')
mdns_major_version = ver_arr[0]
mdns_minor_version = ver_arr[1]
mdns_micro_version = ver_arr[2]

cc = meson.get_compiler('c')

warning_flags = []

warning_flags += [
    '-Wsign-compare',
    '-Wstrict-aliasing',
    '-Wstrict-overflow',
    '-Wformat=2',
    '-Wno-unused-parameter',
    '-Wcast-align',
    '-Wpointer-arith',
    '-Wmissing-prototypes',
    '-Wwrite-strings',
    '-Wlogical-op',
]

add_project_arguments(cc.get_supported_arguments(warning_flags), language: 'c')

cdata = configuration_data()

deps = []
cc_args = []

host_system = host_machine.system()

if host_system == 'windows'
    deps += [cc.find_library('ws2_32')]
    deps += [cc.find_library('iphlpapi')]
    building_for_vista = cc.compiles('''#include <windows.h>
        #ifndef WINVER
        #error "unknown minimum supported OS version"
        #endif
        #if (WINVER < _WIN32_WINNT_VISTA)
        #error "Windows Vista API is not guaranteed"
        #endif
        ''',
        name: 'building for Windows Vista')
    if not building_for_vista
        cc_args = [
            '-D_WIN32_WINNT=_WIN32_WINNT_VISTA',
            '-DWINVER=_WIN32_WINNT_VISTA',
        ]
        add_project_arguments(cc_args, language: 'c')
    endif
endif

inet_ntop_src = '''
#ifdef _WIN32
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
int main() {
  inet_ntop(AF_INET, NULL, NULL, 0);
}
'''

if cc.links(inet_ntop_src, dependencies: deps, args: cc_args)
    cdata.set('HAVE_INET_NTOP', 1)
endif

poll_src = '''
#include <stddef.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
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

if cc.links(poll_src, dependencies: deps, args: cc_args)
    cdata.set('HAVE_POLL', 1)
endif

pollfd_check_prefix = '#include <sys/types.h>\n'

if cdata.get('HAVE_POLL', 0) == 1
    pollfd_check_prefix += '#include <poll.h>\n'
elif host_system == 'windows'
    pollfd_check_prefix += '#include <winsock2.h>'
endif

if cc.has_type('struct pollfd', prefix: pollfd_check_prefix, args: cc_args)
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

link_flags=[]

if get_option('fuzzing')
    if cc.has_argument('-fsanitize=fuzzer')
        fuzz_flags = ['-fsanitize=fuzzer-no-link,address,undefined']
        c_args += fuzz_flags
        c_args += ['-fprofile-instr-generate', '-fcoverage-mapping']
        link_flags += fuzz_flags
        link_flags += ['-fprofile-instr-generate', '-fcoverage-mapping']
    else
        error('Unsupported required option: -fsanitize=fuzzer')
    endif
endif

incdirs = include_directories('.', 'include', 'compat')

subdir('compat')
subdir('include')
subdir('src')

pkg_cdata = configuration_data()

pkg_cdata.set('prefix', join_paths(get_option('prefix')))
pkg_cdata.set('exec_prefix', '${prefix}')
pkg_cdata.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkg_cdata.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))
pkg_cdata.set('VERSION', mdns_version)

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

subdir('examples')
subdir('tests')
