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
    # 0.49 is what Debian 10 ships, according to:
    # https://gitlab.gnome.org/GNOME/glib/blob/master/meson.build
    meson_version   : '>=0.49.2',
    default_options : [
        'buildtype=debugoptimized',
        'c_std=c11',
        'cpp_std=c++17',
        'warning_level=3',
    ]
)

cxx = meson.get_compiler('cpp')

libafl_sources = [
    'src/corpus/entry.cpp',
    'src/engine/engine.cpp',
    'src/executor/inmemory.cpp',
    'src/input/input.cpp',
    'src/mutator/havoc.cpp',
    'src/observer/hitcounts.cpp',
]

deps = []

if host_machine.system() != 'windows'
    # Not windows? Pretty sure we should be in posix land.
    libafl_sources += [
        'src/platform/posix/android-ashmem.h',
        'src/platform/posix/forkserver.cpp',
        'src/platform/posix/shmem.cpp',
    ]
    librt = cxx.find_library('rt', required : false)
    deps += [librt]
endif

incdir = include_directories('include')

libafl = library('libafl', sources: libafl_sources,  include_directories: incdir, dependencies: deps)

executable('main', link_with: libafl, dependencies: deps, include_directories: incdir, sources: ['src/main.cpp'])

inc_test = include_directories('test')
test_catch = executable('test-catch', link_with: libafl, dependencies: deps, include_directories:[incdir, inc_test], sources: [
    'test/catch.hpp',
    'test/corpus/corpus.cpp',
    'test/main.cpp',
])

test('catch', test_catch)

install_data(
    sources: [ 'README.md', 'LICENSE' ],
    install_dir: join_paths(get_option('datadir'), meson.project_name())
    )
