decaf_ss = ss.source_set()

decaf_ss.add(files(
  'decaf-output.c',
  'decaf-basic-callback.c',
  'decaf-main.c',
  'decaf-callback.c',
  'decaf-target.c',
  'decaf-hashtable-wrapper.cpp',
  'decaf-vmi-common.cpp',
  'decaf-linux-vmi.cpp',
  'decaf-linux-procinfo.cpp',
  'decaf-vmi-msg-wrapper.cpp',
  'decaf-taint-memory.c',
  'decaf-taintcheck-opt.c',
  'decaf-taint-tcg.c'
))

specific_ss.add_all(when: 'CONFIG_TCG', if_true: decaf_ss)