sysroot_test = executable('sysroot_test',
  sources: ['sysroot_test.c', '../sysroot.c', '../trace.c'],
  include_directories: include_dir,
  dependencies: [thread_dep],
  c_args: ['-Wno-unused-parameter'],
)
test('sysroot', sysroot_test, suite: 'unit')
test('sysroot_mounts', sysroot_test, args: ['mounts'], suite: 'unit')

signo_test = executable('signo_test',
  sources: ['signo_test.c', '../bsd/signo.c'],
  include_directories: include_dir,
)
test('signo', signo_test, suite: 'unit')

trace_test = executable('trace_test',
  sources: ['trace_test.c', '../trace.c', '../trace_reader.c'],
  include_directories: include_dir,
  dependencies: [thread_dep],
  c_args: ['-Wno-unused-parameter'],
)
test('trace', trace_test, suite: 'unit', workdir: meson.current_build_dir())

sandbox_profile_test = executable('sandbox_profile_test',
  sources: ['sandbox_profile_test.c', '../bsd/sandbox_profile.c'],
  include_directories: include_dir,
)
test('sandbox_profile', sandbox_profile_test, suite: 'unit')

python = import('python').find_installation('python3')
runner = files('run-guest.py')

guest_tests = [
  'acl.c',
  'corefoundation.c',
  'credentials.c',
  'cxx.cpp',
  'dispatch.c',
  'eventlink.c',
  'filesystem.c',
  'fsevents.c',
  'hello.c',
  'iopolicy.c',
  'kqueue.c',
  'kqueue_dispatch2.c',
  'mach.c',
  'necp.c',
  'malloc.c',
  'paths.c',
  'persona.c',
  'protection.c',
  'purgeable.c',
  'restartable.c',
  'route.c',
  'rwlock.c',
  'sandbox.c',
  'sandbox_kept.c',
  'semaphore.c',
  'signals.c',
  'sockets.c',
  'spawn.c',
  'suspend.c',
  'sysinfo.c',
  'terminals.c',
  'threads.c',
  'vm_copy_after_main.c',
  'volumes.c',
  'xpc.c',
]

foreach source : guest_tests
  test(source.split('.')[0], python,
    args: [runner, limbo, files('guest' / source), meson.current_build_dir()],
    suite: 'guest',
    timeout: 300,
  )
endforeach

test('ipc_broker', python,
  args: [runner, limbo, files('guest' / 'ipc_broker.c'),
    meson.current_build_dir(), limbo_broker],
  suite: 'guest',
  timeout: 300,
)

test('traced', python,
  args: [files('run-trace.py'), runner, limbo, limbo_trace,
    files('guest' / 'traced.c'), meson.current_build_dir()],
  suite: 'guest',
  timeout: 300,
)
