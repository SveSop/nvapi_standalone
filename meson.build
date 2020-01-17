project('nvapi', ['c'])

if get_option('enable_d3d11')
  add_project_arguments('-DMESON_BUILD_D3D11', language : 'c')
endif

cpu_family = target_machine.cpu_family()

include_path = include_directories('./include')

lib_d3d11   = declare_dependency(link_args: [ '-ld3d11', '-lpthread' ])
lib_nvml    = declare_dependency(link_args: [ '-lnvidia-ml' ])

winebuild = find_program('winebuild')
winegcc   = find_program('winegcc')
widl         = find_program('widl')

target_arch = cpu_family == 'x86_64' ? '-m64' : '-m32'

def_generator = generator(winebuild,
  output    : [ '@BASENAME@.def' ],
  arguments : [ '-w', ' --def', '--export', '@INPUT@', '-o', '@OUTPUT@' ])

idl_generator = generator(widl,
  output    : [ '@BASENAME@.h' ],
  arguments : [ target_arch, '-o', '@OUTPUT@', '-D__WINESRC__', '@EXTRA_ARGS@', '@INPUT@' ])

subdir('dlls')
