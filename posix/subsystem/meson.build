posix_bragi = cxxbragi.process(protos/'posix/posix.bragi')
devserver_bragi = cxxbragi.process(protos/'posix/devserver.bragi')

src = [
	'src/cgroupfs.cpp',
	'src/clocks.cpp',
	'src/coredump.cpp',
	'src/devserver.cpp',
	'src/device.cpp',
	'src/devices/full.cpp',
	'src/devices/helout.cpp',
	'src/devices/kmsg.cpp',
	'src/devices/null.cpp',
	'src/devices/random.cpp',
	'src/devices/tty.cpp',
	'src/devices/tty0.cpp',
	'src/devices/ttyn.cpp',
	'src/devices/urandom.cpp',
	'src/devices/zero.cpp',
	'src/epoll.cpp',
	'src/eventfd.cpp',
	'src/exec.cpp',
	'src/extern_fs.cpp',
	'src/extern_socket.cpp',
	'src/fifo.cpp',
	'src/file.cpp',
	'src/fs.cpp',
	'src/gdbserver.cpp',
	'src/inotify.cpp',
	'src/interval-timer.cpp',
	'src/link-rc.cpp',
	'src/linux-abi.cpp',
	'src/main.cpp',
	'src/memfd.cpp',
	'src/net.cpp',
	'src/netlink/nl-socket.cpp',
	'src/netlink/nlctrl.cpp',
	'src/netlink/uevent.cpp',
	'src/observations.cpp',
	'src/ostrace.cpp',
	'src/pidfd.cpp',
	'src/process.cpp',
	'src/procfs.cpp',
	'src/pts.cpp',
	'src/requests.cpp',
	'src/requests/common.cpp',
	'src/requests/process.cpp',
	'src/requests/filesystem.cpp',
	'src/requests/memory.cpp',
	'src/requests/socket.cpp',
	'src/requests/timer.cpp',
	'src/requests/special-files.cpp',
	'src/requests/system.cpp',
	'src/requests/fd.cpp',
	'src/requests/uid-gid.cpp',
	'src/signalfd.cpp',
	'src/timerfd.cpp',
	'src/tmp_fs.cpp',
	'src/un-socket.cpp',
	'src/util.cpp',
	'src/vfs.cpp',
	posix_bragi,
	devserver_bragi
]

# vDSO: freestanding DSO, встраивается в posix-subsystem блобом.
if arch == 'x86_64'
	py = import('python').find_installation('python3')

	vdso_so = custom_target('nomilia-vdso.so',
		input : 'vdso/vdso.c',
		output : 'nomilia-vdso.so',
		command : [
			meson.get_compiler('c').cmd_array(),
			'-ffreestanding', '-fPIC', '-O2',
			'-fno-stack-protector', '-fno-asynchronous-unwind-tables',
			'-fno-plt', '-std=gnu11',
			'@INPUT@',
			'-shared', '-nostdlib',
			'-Wl,-z,max-page-size=0x1000',
			'-Wl,--hash-style=both',
			'-Wl,--version-script=' + meson.current_source_dir() / 'vdso/vdso.version',
			'-Wl,-soname,linux-vdso.so.1',
			'-Wl,--no-undefined', '-Wl,--build-id=none',
			'-Wl,-e,__vdso_clock_gettime',
			'-o', '@OUTPUT@'
		]
	)

	vdso_blob = custom_target('vdso-blob.c',
		input : vdso_so,
		output : 'vdso-blob.c',
		command : [py, files('vdso/gen-blob.py'), '@INPUT@', '@OUTPUT@']
	)

	src += [vdso_blob]
endif

executable('posix-subsystem', src,
	dependencies : [ mbus_proto_dep, fs_proto_dep, posix_extra_dep, clock_proto_dep, kerncfg_proto_dep, hw_proto_dep, ostrace_proto_dep, frigg, core_dep ],
	install : true
)

custom_target('posix-subsystem-server',
	command : [bakesvr, '-o', '@OUTPUT@', '@INPUT@'],
	output : 'posix-subsystem.bin',
	input : 'posix-subsystem.yml',
	install : true,
	install_dir : server
)
