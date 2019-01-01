nvencodeapi_src = [
  'nvencodeapi.c',
]

nvencodeapi_dll = shared_library('nvencodeapi.dll', nvencodeapi_src,
  name_prefix         : '',
  include_directories : include_path,
  objects             : 'nvencodeapi.spec',
  install             : true)


nvencodeapi_dll_target = custom_target('nvencodeapi.dll',
  output  : 'nvencodeapi.dll',
  input   : 'nvencodeapi.spec',
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', '@BASENAME@.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvencodeapi_def_target = custom_target('nvencodeapi.def',
  output  : 'nvencodeapi.def',
  input   : 'nvencodeapi.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

