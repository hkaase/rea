"""Record the owned Linux process identity, then replace this process with REA."""

import json
import os
import sys
from pathlib import Path


def main():
    destination = Path(sys.argv[1])
    command = sys.argv[2:]
    stat = Path("/proc/self/stat").read_text()
    identity = {
        "pid": os.getpid(),
        "start_ticks": int(stat.rsplit(")", 1)[1].split()[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(identity) + "\n")
    temporary.replace(destination)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
