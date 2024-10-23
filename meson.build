project('test_pcap_app', 'cpp',
  version: '0.1',
  default_options: ['cpp_std=c++17']
)

cmake = import('cmake')

pcapplusplus_options = cmake.subproject_options()
pcapplusplus_options.add_cmake_defines({
  'PCAPPP_BUILD_EXAMPLES': 'OFF',
  'PCAPPP_BUILD_TESTS': 'OFF',
  'PCAPPP_INSTALL': 'OFF',
})

libpcapplusplus = cmake.subproject('pcap', options: pcapplusplus_options)

pcapplusplus_deps = [
    libpcapplusplus.dependency('Common++'),
    libpcapplusplus.dependency('Packet++'),
    libpcapplusplus.dependency('Pcap++'),
]

libsystemd_dep = dependency('libsystemd', required: true)

sources = files('main.cpp')

dependencies = []
dependencies += dependency('libpcap', static: true)
dependencies += pcapplusplus_deps
dependencies += libsystemd_dep

executable('test_pcap_app',
           sources,
           dependencies: dependencies,
           install: true)

