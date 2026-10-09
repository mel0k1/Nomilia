src = [
	'src/main.cpp',
	'src/badfd.cpp',
	'src/epoll.cpp',
	'src/faults.cpp',
	'src/inotify.cpp',
	'src/parent-dead-signal.cpp',
	'src/pipes.cpp',
	'src/processgroups.cpp',
	'src/signal.cpp',
	'src/signalfd.cpp',
	'src/stat.cpp',
	'src/sync.cpp',
	'src/unixnames.cpp',
	'src/sigaltstack.cpp',
	'src/mmap.cpp',
	'src/memfd.cpp',
	'src/pidfd.cpp',
	'src/socket.cpp',
	'src/timerfd.cpp',
	'src/posix-timers.cpp',
	'src/eventfd.cpp',
	'src/pty.cpp',
	'src/procfs.cpp',
	'src/path-resolution.cpp',
	'src/rename.cpp',
	'src/trailing-slash-create.cpp',
	'src/pthread-fork-wait.cpp',
	'src/thread.cpp',
	'src/poll.cpp',
	'src/segfault.cpp',
	'src/pthread-timeouts.cpp',
	'src/split-mappings.cpp',
	'src/uid-gid.cpp',
	'src/vdso.cpp',
	'src/linux-abi.cpp',
]
if host_machine.cpu_family() == 'x86_64'
	py = import('python').find_installation('python3')
	hello_elf = custom_target('nomilia-linux-hello.elf',
			input : 'linux-hello/hello.S', output : 'nomilia-linux-hello.elf',
			command : [meson.get_compiler('c').cmd_array(), '-nostdlib', '-static', '-no-pie',
					'-Wl,-e,_start', '-Wl,-Ttext=0x400000', '-Wl,--build-id=none',
					'-o', '@OUTPUT@', '@INPUT@'])
	hello_blob = custom_target('linux-hello-blob.c',
			input : hello_elf, output : 'linux-hello-blob.c',
			command : [py, files('gen-hello-blob.py'), '@INPUT@', '@OUTPUT@'])
	files_elf = custom_target('nomilia-linux-files.elf',
				input : 'linux-hello/hello-file.S', output : 'nomilia-linux-files.elf',
				command : [meson.get_compiler('c').cmd_array(), '-nostdlib', '-static', '-no-pie',
						'-Wl,-e,_start', '-Wl,-Ttext=0x400000', '-Wl,--build-id=none',
						'-o', '@OUTPUT@', '@INPUT@'])
	files_blob = custom_target('linux-files-blob.c',
				input : files_elf, output : 'linux-files-blob.c',
				command : [py, files('gen-hello-blob.py'), '@INPUT@', '@OUTPUT@'])
	forky_elf = custom_target('nomilia-linux-forky.elf',
				input : 'linux-hello/forky.S', output : 'nomilia-linux-forky.elf',
				command : [meson.get_compiler('c').cmd_array(), '-nostdlib', '-static', '-no-pie',
						'-Wl,-e,_start', '-Wl,-Ttext=0x400000', '-Wl,--build-id=none',
						'-o', '@OUTPUT@', '@INPUT@'])
	forky_blob = custom_target('linux-forky-blob.c',
				input : forky_elf, output : 'linux-forky-blob.c',
				command : [py, files('gen-hello-blob.py'), '@INPUT@', '@OUTPUT@'])
	dirstat_elf = custom_target('nomilia-linux-dirstat.elf',
				input : 'linux-hello/dirstat.S', output : 'nomilia-linux-dirstat.elf',
				command : [meson.get_compiler('c').cmd_array(), '-nostdlib', '-static', '-no-pie',
						'-Wl,-e,_start', '-Wl,-Ttext=0x400000', '-Wl,--build-id=none',
						'-o', '@OUTPUT@', '@INPUT@'])
	dirstat_blob = custom_target('linux-dirstat-blob.c',
				input : dirstat_elf, output : 'linux-dirstat-blob.c',
				command : [py, files('gen-hello-blob.py'), '@INPUT@', '@OUTPUT@'])
	src += [hello_blob, files_blob, forky_blob, dirstat_blob]
endif
executable('posix-tests', src, dependencies: [cli11_dep, frigg], install : true)
