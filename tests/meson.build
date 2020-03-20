if get_option('tests').disabled()
    subdir_done()
endif

unittest_e = executable('unittest', 'unittests.c',
    include_directories: incdirs,
    link_with: libmicrodns,
    c_args: c_args,
    link_args: link_flags
)

test('unittest', unittest_e)

if get_option('fuzzing')
    executable('mdnsfuzz', 'fuzz.c',
        include_directories: incdirs,
        link_with: libmicrodns,
        link_args: ['-fsanitize=fuzzer,address,undefined', '-lasan', '-lubsan', '-fprofile-instr-generate', '-fcoverage-mapping'],
        c_args: c_args,
    )
endif
