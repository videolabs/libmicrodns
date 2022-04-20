libmicrodns_sources = [
    'mdns.c',
    'rr.c'
]

if host_machine.system() == 'windows'
    mdns_soversion = ''
else
    mdns_soversion = mdns_major_version
endif

libmicrodns = library('microdns', libmicrodns_sources,
    include_directories: incdirs,
    link_with: libcompat,
    link_args: link_flags,
    dependencies: deps,
    c_args: c_args,
    install: true,
    soversion: mdns_soversion,
    version: mdns_soname_version,
)

pkgconf = import('pkgconfig')
pkgconf.generate(libmicrodns,
                 name: 'microDNS',
                 description: 'mDNS simple implementation',
                 filebase: 'microdns',
)
