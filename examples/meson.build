if get_option('examples').disabled()
    subdir_done()
endif

examples_kwargs = {
    'include_directories': incdirs,
    'link_with': libmicrodns,
    'c_args': c_args,
    'link_args': link_flags,
}

executable('listen', 'main.c', kwargs: examples_kwargs)
executable('announce', 'announce.c', kwargs: examples_kwargs)

