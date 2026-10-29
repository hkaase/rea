"""Usage: python -m coordinator CONFIG.json --output PATH"""

import argparse
import asyncio
import json

from .runner import Coordinator, load_config


def main():
    parser = argparse.ArgumentParser(description="Run parallel, isolated REA firmware investigations")
    parser.add_argument("config")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        report = asyncio.run(Coordinator(load_config(args.config), args.output).run())
    except KeyboardInterrupt:
        raise SystemExit(130)
    print(json.dumps({"status": report["status"], "run_directory": report["run_directory"],
                      "peak_active_jobs": report["peak_active_jobs"], "jobs": [{"id": j["id"], "status": j["status"]} for j in report["jobs"]]}))
    raise SystemExit(0 if report["status"] == "completed" else 1)


if __name__ == "__main__":
    main()
