conf = configuration_data()
conf.set('bindir', get_option('bindir'))
conf.set('libdir', get_option('libdir'))
conf.set('arch', target_machine.cpu_family())
configure_file(
  configuration : conf,
  input         : 'setup_nvapi.sh.in',
  output        : 'setup_nvapi.sh',
  install_dir   : get_option('bindir')
)
