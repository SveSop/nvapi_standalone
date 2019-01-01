nvapi64_src = [
  '../nvapi/nvapi.c',
]

nvapi_dll = shared_library('nvapi64.dll', nvapi64_src,
  name_prefix         : '',
  dependencies        : [ lib_wined3d, lib_d3d11 ],
  include_directories : include_path,
  objects             : 'nvapi64.spec',
  install             : true)


nvapi_dll_target = custom_target('nvapi64.dll',
  output  : 'nvapi64.dll',
  input   : 'nvapi64.spec',
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', '@BASENAME@.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvapi_def_target = custom_target('nvapi64.def',
  output  : 'nvapi64.def',
  input   : 'nvapi64.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')
