fdtaf_ss = ss.source_set()

fdtaf_ss.add(files(
  'fdtaf-output.c',
  'fdtaf-basic-callback.c',
  'fdtaf-main.c',
  'fdtaf-callback.c',
  'fdtaf-target.c',
  'fdtaf-hashtable-wrapper.cpp',
  'fdtaf-vmi-common.cpp',
  'fdtaf-linux-vmi.cpp',
  'fdtaf-linux-procinfo.cpp',
  'fdtaf-vmi-msg-wrapper.cpp',
  'fdtaf-taint-memory.c',
  'fdtaf-taintcheck-opt.c',
  'fdtaf-taint-tcg.c',
  'fdtaf-tcpip-parser.c',
  'fdtaf-taint-propagate-msg.c'
))

specific_ss.add_all(when: 'CONFIG_TCG', if_true: fdtaf_ss)