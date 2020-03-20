libmicrodns_sources = [
    'mdns.c',
    'rr.c'
]

libmicrodns = library('microdns', libmicrodns_sources,
    include_directories: incdirs,
    link_with: libcompat,
    link_args: link_flags,
    dependencies: deps,
    c_args: c_args,
    install: true,
)
