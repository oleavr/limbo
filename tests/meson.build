sysroot_test = executable('sysroot_test',
  sources: ['sysroot_test.c', '../sysroot.c'],
  include_directories: include_dir,
  c_args: ['-Wno-unused-parameter'],
)
test('sysroot', sysroot_test, suite: 'unit')

signo_test = executable('signo_test',
  sources: ['signo_test.c', '../bsd/signo.c'],
  include_directories: include_dir,
)
test('signo', signo_test, suite: 'unit')

python = import('python').find_installation('python3')
runner = files('run-guest.py')

guest_tests = [
  'corefoundation.c',
  'credentials.c',
  'cxx.cpp',
  'dispatch.c',
  'filesystem.c',
  'fsevents.c',
  'hello.c',
  'kqueue.c',
  'kqueue_dispatch2.c',
  'mach.c',
  'necp.c',
  'paths.c',
  'persona.c',
  'route.c',
  'sandbox.c',
  'semaphore.c',
  'signals.c',
  'sockets.c',
  'spawn.c',
  'suspend.c',
  'sysinfo.c',
  'threads.c',
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
