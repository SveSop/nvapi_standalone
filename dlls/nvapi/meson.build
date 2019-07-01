nvapi_src = [
  'nvapi.c',
  idl_generator.process('dxvk.idl'),
]


nvapi_res_target = custom_target('nvapi.res',
  output  : 'nvapi.res',
  input   : 'nvapi.rc',
  command : [ find_program('wrc'), '-o', '@OUTPUT@', '--nostdinc', '-I.', '-I'+meson.source_root()+'/include', '-D__WINESRC__', '@INPUT@' ],
  install : false)


nvapi_dll = shared_library('nvapi.dll', nvapi_src,
  name_prefix         : '',
  dependencies        : [ lib_wined3d, lib_d3d11, lib_X11, lib_XNVCtrl, lib_nvml ],
  include_directories : include_path,
  objects             : 'nvapi.spec',
  install             : true)


nvapi_dll_target = custom_target('nvapi.dll',
  output  : 'nvapi.dll',
  input   : [ 'nvapi.spec', nvapi_res_target ],
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', 'nvapi.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvapi_def_target = custom_target('nvapi.def',
  output  : 'nvapi.def',
  input   : 'nvapi.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

