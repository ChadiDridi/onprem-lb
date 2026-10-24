"""Command line: serve, validate, version (and the internal worker command)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

import yaml

from . import __version__, config
from .admin import AdminServer
from .cluster import Cluster, worker_main
from .runtime import Runtime

log = logging.getLogger("onprem_lb")


def load_file(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


async def serve(args: argparse.Namespace) -> int:
    source = args.config
    if args.state_file and os.path.exists(args.state_file):
        source = args.state_file  # API changes made before the restart win
        log.info("loading state from %s", source)
    raw = load_file(source) if source else {}

    workers = (os.cpu_count() or 1) if args.workers == "auto" else int(args.workers)
    if workers > 1:
        rt: Runtime | Cluster = Cluster(workers, args.state_file, args.log_level, not args.no_access_log, not args.no_uvloop)
        await rt.start()
    else:
        rt = Runtime(state_file=args.state_file)
    try:
        cfg = await rt.apply(raw)
        admin = AdminServer(rt, os.environ.get(cfg.admin.token_env))
        await admin.start(cfg.admin.listen_host, cfg.admin.listen_port)
    except BaseException:
        await rt.shutdown(0)
        raise
    n = sum(len(lb.listeners) for lb in cfg.load_balancers.values())
    log.info("onprem-lb %s: %d worker(s), admin API on %s:%d, %d listener(s)", __version__, workers, cfg.admin.listen_host, cfg.admin.listen_port, n)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def reload() -> None:
        if not args.config:
            log.warning("SIGHUP ignored: no --config file to reload")
            return
        try:
            await rt.apply(load_file(args.config))
            log.info("reloaded %s", args.config)
        except (config.ConfigError, OSError, yaml.YAMLError) as e:
            log.error("reload failed, keeping current config: %s", e)

    loop.add_signal_handler(signal.SIGHUP, lambda: asyncio.ensure_future(reload()))
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("shutting down (grace %.0fs)", args.shutdown_grace)
    await admin.stop()
    await rt.shutdown(args.shutdown_grace)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="onprem-lb", description="On-demand on-prem load balancer (L4 NLB + L7 ALB).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the load balancer")
    s.add_argument("-c", "--config", help="YAML config file (reloaded on SIGHUP)")
    s.add_argument("--state-file", help="persist the live config here (API changes survive restarts)")
    s.add_argument("--shutdown-grace", type=float, default=15.0, help="seconds to let connections finish on SIGTERM")
    s.add_argument("--log-level", default=os.environ.get("ONPREM_LB_LOG_LEVEL", "info"))
    s.add_argument("--no-access-log", action="store_true")
    s.add_argument("--no-uvloop", action="store_true", help="use the default asyncio event loop")
    s.add_argument(
        "--workers",
        default=os.environ.get("ONPREM_LB_WORKERS", "1"),
        help="data-plane processes sharing ports via SO_REUSEPORT; 'auto' = one per CPU (default 1)",
    )
    w = sub.add_parser("worker")  # internal: started by `serve --workers N`
    w.add_argument("--control-fd", type=int, required=True)
    w.add_argument("--index", type=int, default=0)
    w.add_argument("--log-level", default="info")
    w.add_argument("--no-access-log", action="store_true")
    w.add_argument("--no-uvloop", action="store_true")
    v = sub.add_parser("validate", help="check a config file and exit")
    v.add_argument("-c", "--config", required=True)
    sub.add_parser("version")
    args = p.parse_args(argv)

    if args.cmd == "version":
        print(__version__)
        return 0
    if args.cmd == "validate":
        try:
            cfg = config.parse(load_file(args.config))
        except (config.ConfigError, OSError, yaml.YAMLError) as e:
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        n = sum(len(lb.listeners) for lb in cfg.load_balancers.values())
        print(f"ok: {len(cfg.load_balancers)} load balancer(s), {n} listener(s), {len(cfg.target_groups)} target group(s)")
        return 0

    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.no_access_log:
        logging.getLogger("onprem_lb.access").setLevel(logging.WARNING)
    if not args.no_uvloop:
        try:
            import uvloop  # type: ignore[import-not-found]

            uvloop.install()
        except ImportError:
            pass
    if args.cmd == "worker":
        return asyncio.run(worker_main(args.control_fd, args.index))
    if args.workers != "auto" and (not str(args.workers).isdigit() or int(args.workers) < 1):
        log.error("--workers must be a positive integer or 'auto'")
        return 2
    try:
        return asyncio.run(serve(args))
    except (config.ConfigError, yaml.YAMLError) as e:
        log.error("invalid config: %s", e)
        return 1
    except (OSError, RuntimeError) as e:
        log.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
