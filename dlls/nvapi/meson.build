nvapi_src = [
  'nvapi.c',
]

nvapi_dll = shared_library('nvapi.dll', nvapi_src,
  name_prefix         : '',
  dependencies        : [ lib_wined3d, lib_d3d11 ],
  include_directories : include_path,
  objects             : 'nvapi.spec',
  install             : true)


nvapi_dll_target = custom_target('nvapi.dll',
  output  : 'nvapi.dll',
  input   : 'nvapi.spec',
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', '@BASENAME@.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvapi_def_target = custom_target('nvapi.def',
  output  : 'nvapi.def',
  input   : 'nvapi.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

