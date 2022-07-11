libcompat_sources = [
    'compat.c',
    'inet.c',
    'poll.c',
]

libcompat = static_library('compat', libcompat_sources,
    include_directories: incdirs,
    dependencies: deps,
    c_args: c_args,
    link_args: link_flags,
    pic: true
)
