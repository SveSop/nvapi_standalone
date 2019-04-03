nvencodeapi64_src = [
  '../nvencodeapi/nvencodeapi.c',
]


nvencodeapi64_res_target = custom_target('nvencodeapi64.res',
  output  : 'nvencodeapi64.res',
  input   : 'nvencodeapi64.rc',
  command : [ find_program('wrc'), '-o', '@OUTPUT@', '--nostdinc', '-I.', '-I'+meson.source_root()+'/include', '-D__WINESRC__', '@INPUT@' ],
  install : false)


nvencodeapi64_dll = shared_library('nvencodeapi64.dll', nvencodeapi64_src,
  name_prefix         : '',
  include_directories : include_path,
  objects             : 'nvencodeapi64.spec',
  install             : true)


nvencodeapi64_dll_target = custom_target('nvencodeapi64.dll',
  output  : 'nvencodeapi64.dll',
  input   : [ 'nvencodeapi64.spec', nvencodeapi64_res_target ],
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', 'nvencodeapi64.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvencodeapi64_def_target = custom_target('nvencodeapi64.def',
  output  : 'nvencodeapi64.def',
  input   : 'nvencodeapi64.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

