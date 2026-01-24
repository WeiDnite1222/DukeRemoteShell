"""
DManager (DuckShell)

Wei - 2025
"""
import inspect
import shlex
import socketserver
from dataclasses import is_dataclass, dataclass, fields, field
import logging
import os
import queue
import sys
import subprocess
import threading
import time
from typing import get_origin, get_args, Union, Any
import click
import requests
import yaml

ROOT_DIR = os.getcwd()
SERVER_CFG = os.path.join(ROOT_DIR, 'srv.yaml')

PAPER_VERSION_API = "https://api.papermc.io/v2/projects/paper/versions/{}"
PAPER_SERVER_JAR_API = "https://api.papermc.io/v2/projects/paper/versions/{}/builds/{}/downloads/paper-{}-{}.jar"
MOJANG_VERSION_MANIFEST_V2 = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"


def download_file(url: str, destination: str, chunk_size: int = 1024 * 512):
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)

    with requests.get(url, stream=True, timeout=30) as r:
        if r.status_code != 200:
            raise Exception(f"Download failed: {r.status_code}\nResponse: {r.text}")

        total = int(r.headers.get("content-length", 0))

        with open(destination, "wb") as f:
            if total > 0:
                with click.progressbar(length=total, label=f"Downloading {os.path.basename(destination)}") as bar:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                            bar.update(len(chunk))
            else:
                click.echo(f"Downloading {os.path.basename(destination)} (unknown size)")
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)


def get_specific_version_paper_builds(minecraft_version: str) -> list[dict[str, str]]:
    """
    Get specific version of Paper builds
    :param minecraft_version:
    :return:
    """
    url = PAPER_VERSION_API.format(minecraft_version)
    try:
        r = requests.get(url)

        if r.status_code == 200:
            return r.json().get("builds", [])
        else:
            raise Exception("Unable to fetch build version for {}\n"
                            "Response: {}".format(minecraft_version, r.text))
    except requests.exceptions.RequestException as e:
        raise Exception("Unable to get paper version from server.\n"
                        "URL: {}\n"
                        "Error: {}".format(url, e))


def get_version_list(release=True):
    try:
        r = requests.get(MOJANG_VERSION_MANIFEST_V2)

        if r.status_code == 200:
            if release:
                return [version.get('id') for version in r.json().get("versions", [])
                        if version.get("type") == "release" if version.get('id') is not None]
            return r.json()["versions"]
        else:
            raise Exception("Unable to fetch version list.\n"
                            "Response: {}".format(r.text))
    except requests.exceptions.RequestException as e:
        raise Exception("Unable to get version list from server.\n"
                        "URL: {}\n"
                        "Error: {}".format(MOJANG_VERSION_MANIFEST_V2, e))


def get_latest_version_minecraft(release=True):
    version_list = get_version_list(release=release)
    ver = version_list[0].get("id") if version_list else None

    if ver is None:
        raise Exception("Unable to find latest version in version list.\n")

    return ver


def download_server_jar(minecraft_version: str, build_version: str, destination_dir: str, filename: str | None = None):
    """
    Download server jar (paper server only)
    """
    url = PAPER_SERVER_JAR_API.format(minecraft_version, build_version, minecraft_version, build_version)

    if filename:
        jar_name = filename
        if not jar_name.endswith(".jar"):
            jar_name += ".jar"
    else:
        jar_name = os.path.basename(url)

    destination_path = os.path.join(destination_dir, jar_name)

    try:
        download_file(url, destination_path)
        return destination_path
    except Exception as e:
        raise Exception("Unable to download server jar for version {}\nURL: {}\nError: {}".format(minecraft_version, url, e))


def get_latest_build_of_version(minecraft_version: str) -> str:
    builds = get_specific_version_paper_builds(minecraft_version)
    if not builds:
        raise Exception(f"No builds found for Paper {minecraft_version}")
    # Paper API usually lists builds ascending; latest is the last one
    return str(builds[-1])


def download_latest_build_paper_jar(minecraft_version: str, destination_dir: str, filename: str | None = None):
    build = get_latest_build_of_version(minecraft_version)
    return download_server_jar(minecraft_version, build, destination_dir, filename=filename)


def download_latest_paper_jar(destination_dir: str, filename: str | None = None, release: bool = True):
    """
    Download latest Minecraft version (release) paper jar
    """
    vers = get_version_list(release=release)

    if len(vers) == 0:
        raise Exception("No versions available for Minecraft (Did the server return wrong response ?)")

    latest_mc = vers[0]
    return download_latest_build_paper_jar(latest_mc, destination_dir, filename=filename)

@click.group()
def main():
    print("DManager\n"
          "WorkDir: {}".format(ROOT_DIR))

@main.command()
@click.option("--dest", "-d", default=".", show_default=True,
              help="The destination of the server folder (Default is current directory)")
@click.option("--mc-version", "-m",
              default=None,
              help="Specify Minecraft version to download (If not specified, download latest Minecraft version)", required=False)
@click.option("--build", "-b", default=None,
              help="Specify paper build to download (Use latest Minecraft version if not specified)")
@click.option("--snapshot", is_flag=True, help="Download snapshot version Minecraft (Use it if the current mc-version type is snapshot)")
@click.option("--latest", is_flag=True, help="Download latest Minecraft version (With latest build paper)")
@click.option("--list-builds", is_flag=True, help="List available paper build versions")
@click.option("--filename", default=None, help="Custom SERVER.jar file name")
def create_server(dest, mc_version, build, snapshot, latest, list_builds, filename):
    try:
        release = True if not snapshot else False
        if latest:
            click.echo("Fetching latest Mojang release version...")
            out = download_latest_paper_jar(dest, filename=filename, release=release)
            click.echo(f"Done: {out}")
            return

        if mc_version is None:
            click.echo("The mc-version is not specified. Fetching latest Minecraft release version...")
            mc_version = get_latest_version_minecraft(release=release)

        if list_builds:
            builds = get_specific_version_paper_builds(mc_version)
            if not builds:
                click.echo(f"No builds found for Paper {mc_version}")
                return
            click.echo(f"Paper {mc_version} builds:")
            click.echo(", ".join(map(str, builds[-20:])))
            click.echo("(Only list latest 20 builds)")
            return

        if build:
            click.echo(f"Downloading Paper {mc_version} build {build} ...")
            out = download_server_jar(mc_version, str(build), dest, filename=filename)
            click.echo(f"Done: {out}")
        else:
            click.echo(f"Downloading latest Paper build for {mc_version} ...")
            out = download_latest_build_paper_jar(mc_version, dest, filename=filename)
            click.echo(f"Done: {out}")

    except Exception as e:
        raise click.ClickException(str(e))


def to_plain(obj):
    # Basic types
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # Instances
    if isinstance(obj, list):
        return [to_plain(x) for x in obj]
    if isinstance(obj, tuple):
        return [to_plain(x) for x in obj]  # YAML 沒 tuple，轉成 list
    if isinstance(obj, set):
        return [to_plain(x) for x in obj]  # set 也轉 list
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}

    # dataclass
    if is_dataclass(obj):
        data = {}
        for f in fields(obj):
            data[f.name] = to_plain(getattr(obj, f.name))
        return data

    # Use __dict__ if object support this method
    if hasattr(obj, "__dict__"):
        return {str(k): to_plain(v) for k, v in obj.__dict__.items()}

    # Return str if obj is not serializable
    return str(obj)


def to_object(obj):
    # 基本型別
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # 容器
    if isinstance(obj, list):
        return [to_object(x) for x in obj]
    if isinstance(obj, tuple):
        return [to_object(x) for x in obj]
    if isinstance(obj, set):
        return [to_object(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_object(v) for k, v in obj.items()}

    # dataclass
    if is_dataclass(obj):
        return {f.name: to_object(getattr(obj, f.name)) for f in fields(obj)}

    # 普通 class
    if hasattr(obj, "__dict__"):
        return {str(k): to_object(v) for k, v in obj.__dict__.items()}

    # fallback
    return str(obj)


def build(tp, data):
    if data is None:
        return None

    origin = get_origin(tp)
    args = get_args(tp)

    # Optional / Union
    if origin is Union:
        for sub in args:
            if sub is type(None):
                continue
            try:
                return build(sub, data)
            except Exception:
                pass
        return data

    # list[T]
    if origin is list:
        (item_type,) = args
        return [build(item_type, x) for x in data]

    # dict[K, V]
    if origin is dict:
        k_t, v_t = args
        return {build(k_t, k): build(v_t, v) for k, v in data.items()}

    # 基本型別
    if tp in (str, int, float, bool):
        return tp(data)

    # dataclass
    if inspect.isclass(tp) and is_dataclass(tp):
        kwargs = {}
        for f in fields(tp):
            if f.name in data:
                kwargs[f.name] = build(f.type, data[f.name])
        return tp(**kwargs)

    # 普通 class：依照 __init__ 的參數與 annotations 建構
    if inspect.isclass(tp):
        sig = inspect.signature(tp.__init__)
        type_hints = getattr(tp.__init__, "__annotations__", {})

        kwargs = {}
        for name, param in sig.parameters.items():
            if name == "self":
                continue
            if name in data:
                ann = type_hints.get(name, Any)
                kwargs[name] = build(ann, data[name])
        return tp(**kwargs)

    return data

class ServerConfig:
    def __init__(self):
        self.restart_after_crash: bool = False
        self.retry_times: int = 5
        self.dump_crash_log: bool = False

class ServerObjectInConfig:
    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        command: str,
        work_dir: str,
        host: str,
        port: int,
        future: dict[str, Any] | None = None,
    ):
        self.name = name
        self.version = version
        self.description = description
        self.command = command
        self.work_dir = work_dir
        self.future = future or {}
        self.config = ServerConfig()
        self.host = host
        self.port = port


@dataclass
class ServerListConfig:
    servers: list[ServerObjectInConfig] = field(default_factory=list)
    future: dict[str, Any] = field(default_factory=dict)


@main.command()
@click.option("--srv-config-path", "-svp",
              help="The destination of the srv.yaml (Auto create if the config file does not exist)", required=True)
@click.option("--server-folder-path", "-sf",
              help="The destination of the folder", required=True)
@click.option("--server-jar-path", "-sp",
              help="The destination of the SERVER.jar", required=True)
@click.option("--socket-server-host", "-srh",
              help="Hostname of the socket server", required=True)
@click.option("--socket-server-port", "-srp",
              help="Port of the socket server", required=True)
@click.option("--java-exec-path", "-p", show_default=True,
              help="The destination of the java executable", default="java")
@click.option("--x-memory-initial", "-xms", show_default=True,
              help="Initial allocation size of the memory for server",
              type=str, default="1G")
@click.option("--x-memory-maximum", "--xmx", show_default=True,
              help="Maximum allocation size of the memory for server",
              type=str, default="4G")
@click.option("--nogui", "-ng",
              help="Disable server window",
              is_flag=True)
@click.option("--extra-args", "-e",
              help="Extra java arguments", type=str, default="")
def create_bootstrap(srv_config_path, server_folder_path, server_jar_path, socket_server_host, socket_server_port, java_exec_path, x_memory_initial, x_memory_maximum, nogui, extra_args):
    global srv_obj
    srv_object = None
    if not os.path.exists(srv_config_path):
        srv_obj = ServerListConfig()
        try:
            with open(srv_config_path, "w") as srv:
                srv.write(yaml.safe_dump(to_object(srv_obj)))
        except Exception as e:
            raise click.ClickException("Failed to create srv.yaml. Error: {}".format(e))
    else:
        with open(srv_config_path, "r") as srv:
            data = yaml.safe_load(srv)
            srv_obj = build(ServerListConfig, data)

    if srv_obj is None:
        raise click.ClickException("Failed to create srv.yaml")

    print("There's some information you need to fill for server config.")
    name = str(input("New server name: "))
    version = str(input("Server version: "))
    desc = str(input("Server description: "))

    extra_args += " nogui" if nogui else ""
    cmd = f"{java_exec_path} -Xms{x_memory_initial} -Xmx{x_memory_maximum} -jar {server_jar_path} {extra_args}"
    print(f"Server command: {cmd}")

    server = ServerObjectInConfig(
        name=name,
        version=version,
        description=desc,
        command=cmd,
        work_dir=server_folder_path,
        port=socket_server_port,
        host=socket_server_host,
    )

    srv_obj.servers.append(server)

    print("Saving...")
    with open(srv_config_path, "w", encoding="utf-8") as f:
        f.write(yaml.safe_dump(to_object(srv_obj), allow_unicode=True, sort_keys=False))


class Server:
    def __init__(self, logger, config: ServerObjectInConfig):
        self.logger = logger
        self._stdout_thread = None
        self.config = config

        self.proc: subprocess.Popen | None = None
        self.proc_lock = threading.Lock()

        self.running = False
        self.stopping = False

        self.log_queue = queue.Queue()  # stdout lines
        self._threads: list[threading.Thread] = []

        # socket server
        self._tcp_server: socketserver.ThreadingTCPServer | None = None
        self._tcp_thread: threading.Thread | None = None

        self._log_subscribers: set[queue.Queue] = set()
        self._sub_lock = threading.Lock()

    def start_process(self):
        self.logger.info("Starting process...")

        with self.proc_lock:
            if self.proc and self.proc.poll() is None:
                self.logger.warning("[PROC] already running, skip")
                return

            args = shlex.split(self.config.command)

            self.logger.info("[PROC] spawning: %s", self.config.command)

            self.proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=self.config.work_dir
            )

            self.logger.info(f"[PROC] Process spawned. PID = {self.proc.pid}")

            self._stdout_thread = threading.Thread(target=self._stdout_reader_loop, daemon=True)
            self._stdout_thread.start()

    def _stdout_reader_loop(self):
        self.logger.info("[PROC] stdout reader started")
        while self.running:
            with self.proc_lock:
                proc = self.proc
                out = proc.stdout if proc else None

            if not proc or proc.poll() is not None or not out:
                self.logger.info("[PROC] process ended / stdout closed")
                break

            line = out.readline()
            if not line:
                break

            line = line.rstrip("\n")
            self.logger.info("[PROC] %s", line)
            self.publish_log(line)

    def send_command(self, command: str) -> bool:
        with self.proc_lock:
            if not self.proc or self.proc.poll() is not None:
                return False
            if not self.proc.stdin:
                return False

            self.proc.stdin.write(command + "\n")
            self.proc.stdin.flush()
            return True

    def stop_process(self, timeout: float = 10.0):
        with self.proc_lock:
            proc = self.proc

        if not proc:
            return

        # Minecraft only
        self.send_command("stop")

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        with self.proc_lock:
            self.proc = None

    # -------------------------
    # Socket Server
    # -------------------------
    def publish_log(self, line: str):
        # 這裡由 stdout reader 呼叫
        with self._sub_lock:
            for q in list(self._log_subscribers):
                try:
                    q.put_nowait(line)
                except queue.Full:
                    pass

    def subscribe_logs(self) -> queue.Queue:
        q = queue.Queue(maxsize=2000)
        with self._sub_lock:
            self._log_subscribers.add(q)
        return q

    def unsubscribe_logs(self, q: queue.Queue):
        with self._sub_lock:
            self._log_subscribers.discard(q)

    def handler_command(self, command: str):
        self.logger.info("Handling command: %s", command)

    def _build_tcp_server(self):
        manager = self

        class TCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

            def __init__(self, server_address, RequestHandlerClass):
                super().__init__(server_address, RequestHandlerClass)
                self.manager = manager  # 直接嵌進 server instance

        class Handler(socketserver.BaseRequestHandler):
            def setup(self):
                mgr: Server = self.server.manager

                mgr.logger.info(f"[SYS] Client from {self.client_address[0]}:{self.client_address[1]} connected,")


            def handle(self):
                mgr: Server = self.server.manager

                log_q = mgr.subscribe_logs()
                stop_evt = threading.Event()

                def push_logs():
                    while not stop_evt.is_set():
                        try:
                            line = log_q.get(timeout=0.5)
                        except Exception:
                            continue
                        try:
                            self.request.sendall(f"[LOG] {line}\n".encode("utf-8"))
                        except OSError:
                            break

                t = threading.Thread(target=push_logs, daemon=True)
                t.start()

                try:
                    self.request.sendall(b"[SYS] connected\n")
                    buf = b""

                    while True:
                        data = self.request.recv(4096)
                        if not data:
                            break

                        buf += data
                        while b"\n" in buf:
                            raw, buf = buf.split(b"\n", 1)
                            cmd = raw.decode("utf-8", errors="ignore").strip()

                            if not cmd:
                                continue

                            mgr.logger.info(f"[SYS] Client from {self.client_address[0]}:{self.client_address[1]} send command: {cmd}")

                            if cmd.startswith("__"):
                                if cmd == "__exit":
                                    self.request.sendall(b"[SYS] bye\n")
                                    return
                                elif cmd == "__status":
                                    alive = mgr.is_process_alive()
                                    self.request.sendall(
                                        f"[SYS] process_alive={alive}\n".encode("utf-8")
                                    )
                                    continue
                                else:
                                    mgr.handler_command(cmd)
                            else:
                                ok = mgr.send_command(cmd)

                            msg = f"[OK] Command received. {cmd}\n" if ok else "[ERR] An error occurred\n"
                            self.request.sendall(msg.encode("utf-8"))
                except ConnectionResetError:
                    mgr.logger.info("[SYS] Client disconnected. From {}:{}".format(self.client_address[0], self.client_address[1]))
                finally:
                    stop_evt.set()
                    mgr.unsubscribe_logs(log_q)

        return TCPServer((self.config.host, self.config.port), Handler)

    def start_socket_server(self):
        if self._tcp_server:
            print("[SOCK] already running")
            return

        self._tcp_server = self._build_tcp_server()

        def loop():
            self.logger.info(f"[SOCK] listening on {self.config.host}:{self.config.port}")
            self._tcp_server.serve_forever(poll_interval=0.5)

        self._tcp_thread = threading.Thread(target=loop, daemon=True)
        self._tcp_thread.start()

    def stop_socket_server(self):
        if not self._tcp_server:
            return
        self.logger.info("[SOCK] shutting down")
        self._tcp_server.shutdown()
        self._tcp_server.server_close()
        self._tcp_server = None

    # -------------------------
    # Manager lifecycle
    # -------------------------
    def start(self):
        if self.running:
            return
        self.running = True
        self.stopping = False

        self.start_process()
        self.start_socket_server()

    def stop(self):
        if not self.running:
            return

        self.stopping = True
        self.running = False

        self.stop_socket_server()

        self.stop_process()

    def is_process_alive(self) -> bool:
        with self.proc_lock:
            return self.proc is not None and self.proc.poll() is None

def load_all_server_cfg(cfg_path):
    if not os.path.isfile(cfg_path) or not os.path.exists(cfg_path):
        raise FileNotFoundError("The config file does not exist. At {}".format(cfg_path))

    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)

    server_list_cfg = build(ServerListConfig, cfg)

    return server_list_cfg


@main.command()
@click.option("-sc", "--server-config-path", default=SERVER_CFG, help="Server list config file path")
def runserver(server_config_path):
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s: %(message)s')
    logger.setLevel(logging.INFO)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    server_list_config = load_all_server_cfg(server_config_path)
    print("{} servers available".format(len(server_list_config.servers)))
    logger.info("Starting server")

    servers = []
    for server_cfg in server_list_config.servers:
        formatter = logging.Formatter('%(name)s: %(message)s')
        logger = logging.getLogger("[{}]".format(server_cfg.name))
        logger.setLevel(logging.INFO)

        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.INFO)
        stdout_handler.setFormatter(formatter)
        logger.addHandler(stdout_handler)

        sv = Server(logger, server_cfg)
        servers.append(sv)
        sv.start()

    while any(sv.is_process_alive() for sv in servers):
        time.sleep(1)

if __name__ == "__main__":
    main()