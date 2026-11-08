"""A TCP relay that breaks on command, for the Step 19 chaos gate.

Sits between a client and a server (the card service and one acquirer, or a terminal and the API) and passes
bytes both ways until told otherwise:

* `refuse()`: every connection is reset, now and on arrival: a dead host or a cut network.
* `swallow()`: requests still reach the server, but nothing it sends comes back: a host that processes the
  payment and then goes dark, which is exactly when an outcome is unknown.
* `heal()`: back to passing. Connections broken earlier stay broken; clients reconnect.

TLS passes through untouched, so mutual-TLS clients and servers don't know it is there.
"""
import socket
import threading


class FaultProxy:
    def __init__(self, target_port: int, target_host: str = "127.0.0.1"):
        self.target = (target_host, target_port)
        self.mode = "pass"
        self._sockets: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def refuse(self) -> None:
        self.mode = "refuse"
        self._reset_all()

    def swallow(self) -> None:
        self.mode = "swallow"

    def heal(self) -> None:
        self.mode = "pass"

    def close(self) -> None:
        self.mode = "closed"
        self._listener.close()
        self._reset_all()

    def _accept(self) -> None:
        while self.mode != "closed":
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            if self.mode == "refuse":
                _reset(client)
                continue
            try:
                upstream = socket.create_connection(self.target, timeout=5)
                upstream.settimeout(None)
            except OSError:
                _reset(client)
                continue
            with self._lock:
                self._sockets.update((client, upstream))
            threading.Thread(target=self._pump, args=(client, upstream, False), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, True), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket, from_server: bool) -> None:
        try:
            while data := src.recv(65536):
                if self.mode == "refuse":
                    break
                if from_server and self.mode == "swallow":
                    continue  # the answer is lost on the way back
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                _reset(s)
                with self._lock:
                    self._sockets.discard(s)

    def _reset_all(self) -> None:
        with self._lock:
            sockets, self._sockets = list(self._sockets), set()
        for s in sockets:
            _reset(s)


class FailoverProxy:
    """A one-line global load balancer: each new connection goes to the first target that accepts it, in order.
    Stands in for DNS failover between regions; existing connections are not moved."""

    def __init__(self, target_ports: list[int]):
        self.targets = [("127.0.0.1", p) for p in target_ports]
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self.served_by: list[int] = []  # target port of every connection, in order
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            upstream = None
            for target in self.targets:
                try:
                    upstream = socket.create_connection(target, timeout=0.5)
                    upstream.settimeout(None)
                    self.served_by.append(target[1])
                    break
                except OSError:
                    continue
            if upstream is None:
                _reset(client)
                continue
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=_relay, args=(src, dst), daemon=True).start()

    def close(self) -> None:
        self._listener.close()


def _relay(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        _reset(src)
        _reset(dst)


def _reset(s: socket.socket) -> None:
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")  # RST, not FIN
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass
