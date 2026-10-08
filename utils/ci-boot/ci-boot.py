#!/usr/bin/python3 -u

import asyncio
import base64
import json
import os

DEBUG = False


class CiBoot:
    def __init__(self, pipe):
        self.pipe = pipe

    async def run(self):
        print("Ready for commands")
        self._emit({"m": "ready"})
        for line in self.pipe:
            if DEBUG:
                print("Received line:", repr(line))
            try:
                msg = json.loads(line)
                if msg["m"] == "launch":
                    script = msg["script"]
                    await self._launch(script)
                elif msg["m"] == "download":
                    path = msg["path"]
                    with open(path, "rb") as f:
                        while True:
                            data = f.read(4096)
                            if data:
                                self._emit({"m": "download-data", "data": base64.b64encode(data).decode("ascii"), "path": path})
                            else:
                                break
                elif msg["m"] == "done":
                    self._emit({"m": "done"})
                    return
                else:
                    raise RuntimeError("Bad message type: " + msg["m"])
            except Exception as e:
                print("Error:", str(e))
                self._emit({"m": "error", "text": str(e)})

    async def _launch(self, script):
        print("Launching script:", repr(script))

        # Use a PTY to force line buffering.
        master_fd, slave_fd = os.openpty()
        try:
            process = await asyncio.create_subprocess_exec(
                "/usr/bin/bash",
                "-c",
                script,
                stdout=slave_fd,
                stderr=slave_fd,
            )
        finally:
            os.close(slave_fd)

        await asyncio.gather(
            self._handle_output("stdout", master_fd),
            process.wait(),
        )

        os.close(master_fd)

        print(f"Script terminated with {process.returncode}")
        self._emit({"m": "exit", "exitcode": process.returncode})

    async def _handle_output(self, kind, fd):
        loop = asyncio.get_event_loop()
        done = asyncio.Event()

        partial = b""
        def on_readable():
            nonlocal partial
            try:
                data = os.read(fd, 4096)
            except OSError:
                # Linux emits EIO when the slave PTY is closed.
                data = b""
            # Stop reading on zero length read or EIO.
            if not data:
                if partial:
                    print(f"{kind}: " + partial.rstrip().decode("utf8", errors="backslashreplace"))
                    self._emit({"m": kind, "data": base64.b64encode(partial).decode("ascii")})
                loop.remove_reader(fd)
                done.set()
                return
            partial += data
            while b"\n" in partial:
                line, partial = partial.split(b"\n", 1)
                line += b"\n"
                print(f"{kind}: " + line.rstrip().decode("utf8", errors="backslashreplace"))
                self._emit({"m": kind, "data": base64.b64encode(line).decode("ascii")})

        loop.add_reader(fd, on_readable)
        await done.wait()

    def _emit(self, msg):
        line = json.dumps(msg)
        self.pipe.write(line.encode("utf8") + b"\n")


async def main():
    with open("/dev/ttyS0", "rb+", buffering=0) as f:
        ciboot = CiBoot(f)
        await ciboot.run()


if __name__ == "__main__":
    asyncio.run(main())
