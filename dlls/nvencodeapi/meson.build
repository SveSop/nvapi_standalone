nvencodeapi_src = [
  'nvencodeapi.c',
]


nvencodeapi_res_target = custom_target('nvencodeapi.res',
  output  : 'nvencodeapi.res',
  input   : 'nvencodeapi.rc',
  command : [ find_program('wrc'), '-o', '@OUTPUT@', '--nostdinc', '-I.', '-I'+meson.source_root()+'/include', '-D__WINESRC__', '@INPUT@' ],
  install : false)


nvencodeapi_dll = shared_library('nvencodeapi.dll', nvencodeapi_src,
  name_prefix         : '',
  include_directories : include_path,
  dependencies        : [ lib_dl ],
  objects             : 'nvencodeapi.spec',
  install             : true)


nvencodeapi_dll_target = custom_target('nvencodeapi.dll',
  output  : 'nvencodeapi.dll',
  input   : [ 'nvencodeapi.spec', nvencodeapi_res_target ],
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', 'nvencodeapi.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvencodeapi_def_target = custom_target('nvencodeapi.def',
  output  : 'nvencodeapi.def',
  input   : 'nvencodeapi.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

