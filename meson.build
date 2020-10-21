###################################################################################
#                                                                                 #
# NAME: meson.build                                                               #
#                                                                                 #
# AUTHOR: LibAFL authors.                                                         #
#                                                                                 #
# CONTACT: <mailto:mail@aflplus.plus>                                             #
#                                                                                 #
# NOTICES:                                                                        #
#                                                                                 #
# License: LGPL 2.1                                                               #
#                                                                                 #
###################################################################################



project('libafl', 'cpp',
    version         : '0.0.1',
    license         : 'LGPL',
    meson_version   : '>=0.50.0',
    default_options : ['cpp_std=c++17']
    )


libafl_deps = [
    'src/corpus/entry.cpp',
    'src/engine/engine.cpp',
    'src/executor/inmemory.cpp',
    'src/input/input.cpp',
    'src/mutator/havoc.cpp',
    'src/observer/hitcounts.cpp',
]

if host_machine.system() != 'windows'
    # Not windows? Pretty sure we should be in posix land.
    libafl_deps += [
        'src/platform/posix/android-ashmem.h',
        'src/platform/posix/forkserver.cpp',
        'src/platform/posix/shmem.cpp',
    ]
endif

incdir = include_directories('include')

libafl = library('libafl', sources: libafl_deps, include_directories: incdir)

executable('main', link_with: libafl, include_directories: incdir, sources: ['src/main.cpp'])

inc_test = include_directories('test')
test_catch = executable('test-catch', link_with: libafl, include_directories:[incdir, inc_test], sources: [
    'test/catch.hpp',
    'test/corpus/corpus.cpp',
    'test/main.cpp',
])

test('catch', test_catch)

install_data(
    sources: [ 'README.md', 'LICENSE' ],
    install_dir: join_paths(get_option('datadir'), meson.project_name())
    )
