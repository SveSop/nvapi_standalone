nvcuda_src = [
  'internal.c',
  'nvcuda.c',
]

thread_dep = dependency('threads')

nvcuda_res_target = custom_target('nvcuda.res',
  output  : 'nvcuda.res',
  input   : 'nvcuda.rc',
  command : [ find_program('wrc'), '-o', '@OUTPUT@', '--nostdinc', '-I.', '-I'+meson.source_root()+'/include', '-D__WINESRC__', '@INPUT@' ],
  install : false)


nvcuda_dll = shared_library('nvcuda.dll', nvcuda_src,
  name_prefix         : '',
  dependencies        : [ thread_dep, lib_dl ],
  include_directories : include_path,
  objects             : 'nvcuda.spec',
  install             : true)


nvcuda_dll_target = custom_target('nvcuda.dll',
  output  : 'nvcuda.dll',
  input   : [ 'nvcuda.spec', nvcuda_res_target ],
  command : [ winebuild, target_arch, '--dll', '--fake-module', '-E', '@INPUT@', '-o', '@OUTPUT@', '-F', 'nvcuda.dll' ],
  install : true,
  install_dir : 'fakedlls')


nvcuda_def_target = custom_target('nvcuda.def',
  output  : 'nvcuda.def',
  input   : 'nvcuda.spec',
  command : [ winebuild, target_arch, '-w', '--def', '--export', '@INPUT@', '-o', '@OUTPUT@' ],
  install : true,
  install_dir : 'defs')

