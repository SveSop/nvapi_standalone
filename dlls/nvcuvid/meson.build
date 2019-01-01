nvcuvid_src = [
  'nvcuvid.c',
]

nvcuvid_dll = shared_library('nvcuvid.dll', nvcuvid_src,
  name_prefix         : '',
  include_directories : include_path,
  objects             : 'nvcuvid.spec',
  install             : true)


nvcuvid_dll_target = custom_target('nvcuvid.dll',
  output  : 'nvcuvid.dll',
  input   : 'nvcuvid.spec',
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', '@BASENAME@.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvcuvid_def_target = custom_target('nvcuvid.def',
  output  : 'nvcuvid.def',
  input   : 'nvcuvid.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

