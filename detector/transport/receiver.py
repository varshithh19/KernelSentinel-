import socket
import threading
import json
import time
import collections
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ValidationError, ConfigDict

class KernelTelemetryEvent(BaseModel):
    """
    Validated Schema for incoming kernel telemetry events from BCC tracer or C collector.
    Strictly validated with bounded types.
    """
    model_config = ConfigDict(extra="allow")

    type: str = Field(..., description="Normalized event type: exec, open, connect, read, write, fork, socket")
    pid: int = Field(..., ge=0, description="Process ID (non-negative integer)")
    tgid: Optional[int] = Field(None, ge=0, description="Thread Group ID")
    uid: Optional[int] = Field(None, ge=0, description="User ID")
    comm: Optional[str] = Field(None, max_length=64, description="Process command name")
    filename: Optional[str] = Field(None, max_length=512, description="Target file path")
    flags: Optional[int] = Field(None, description="Open flags or file mode")
    daddr: Optional[str] = Field(None, max_length=64, description="Destination IPv4/IPv6 address")
    dport: Optional[int] = Field(None, ge=0, le=65535, description="Destination TCP/UDP port")
    ret: Optional[int] = Field(None, description="Syscall return value")
    details: Optional[str] = Field(None, description="Detailed trace information")
    ts_ns: Optional[int] = Field(None, description="Kernel timestamp in nanoseconds")
    ts: Optional[float] = Field(None, description="Event wall clock timestamp in seconds")
    syscall: Optional[str] = Field(None, max_length=32, description="Syscall name (e.g. execve, openat)")
    provenance: str = Field("kernel_ebpf", description="Provenance marker: kernel_ebpf or simulated")



class TelemetryReceiver:
    """
    Localhost-only TCP Event Receiver for KernelSentinel Telemetry.
    - Binds exclusively to 127.0.0.1 (rejects non-localhost bindings).
    - Implements newline-delimited message framing.
    - Enforces maximum line length (max_message_bytes) to prevent unbounded memory growth.
    - Validates incoming events against KernelTelemetryEvent schema.
    - Maintains a thread-safe, bounded in-memory ring buffer of recent events.
    """
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9090,
        max_message_bytes: int = 65536,
        max_buffer_size: int = 10000
    ):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(f"TelemetryReceiver is strictly localhost-only (127.0.0.1), got '{host}'")
        self.host = host
        self.port = port
        self.max_message_bytes = max_message_bytes
        self.max_buffer_size = max_buffer_size

        self.events_buffer: collections.deque[Dict[str, Any]] = collections.deque(maxlen=max_buffer_size)
        self.lock = threading.Lock()
        self.is_running = False

        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None

        self.stats = {
            "events_received": 0,
            "events_valid": 0,
            "events_malformed": 0,
            "events_oversized": 0,
            "connections_count": 0,
        }

    @property
    def running(self) -> bool:
        return self.is_running


    def start(self):
        """Starts the localhost TCP server thread."""
        if self.is_running:
            return

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))

        # If port was 0, capture OS-assigned ephemeral port
        if self.port == 0:
            self.port = self._server_socket.getsockname()[1]

        self._server_socket.listen(128)
        self._server_socket.settimeout(0.5)
        self.is_running = True

        self._server_thread = threading.Thread(
            target=self._accept_loop,
            name="KernelSentinel-TelemetryReceiver",
            daemon=True
        )
        self._server_thread.start()

    def stop(self):
        """Stops the receiver and closes active sockets cleanly."""
        self.is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=1.0)
            self._server_thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _accept_loop(self):
        while self.is_running:
            try:
                client_sock, client_addr = self._server_socket.accept()
            except socket.timeout:
                continue
            except Exception:
                if not self.is_running:
                    break
                continue

            with self.lock:
                self.stats["connections_count"] += 1

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, client_addr),
                daemon=True
            )
            client_thread.start()

    def _handle_client(self, client_sock: socket.socket, client_addr):
        client_sock.settimeout(2.0)
        buffer = bytearray()

        try:
            while self.is_running:
                try:
                    chunk = client_sock.recv(4096)
                except socket.timeout:
                    continue
                except Exception:
                    break

                if not chunk:
                    break

                buffer.extend(chunk)

                # Process newline-delimited frames
                while b"\n" in buffer:
                    line_end = buffer.index(b"\n")
                    line_bytes = buffer[:line_end]
                    del buffer[:line_end + 1]

                    if len(line_bytes) > self.max_message_bytes:
                        with self.lock:
                            self.stats["events_oversized"] += 1
                        continue

                    # Strip carriage return if present
                    if line_bytes.endswith(b"\r"):
                        line_bytes = line_bytes[:-1]

                    if not line_bytes:
                        continue

                    self._process_message(line_bytes)

                # If remainder in buffer without newline exceeds max bounded size, discard
                if len(buffer) > self.max_message_bytes:
                    with self.lock:
                        self.stats["events_oversized"] += 1
                    buffer.clear()

        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_message(self, raw_bytes: bytes):
        with self.lock:
            self.stats["events_received"] += 1

        try:
            text = raw_bytes.decode("utf-8")
            data = json.loads(text)
        except Exception:
            with self.lock:
                self.stats["events_malformed"] += 1
            return

        if not isinstance(data, dict):
            with self.lock:
                self.stats["events_malformed"] += 1
            return

        try:
            # Set default timestamp if not provided
            if "ts" not in data or data["ts"] is None:
                data["ts"] = round(time.time(), 4)
            # Ensure provenance is set
            if "provenance" not in data:
                data["provenance"] = "kernel_ebpf"

            # Normalize type/syscall if needed
            if "type" not in data and "syscall" in data:
                sc = data["syscall"]
                if sc in ("openat", "open"):
                    data["type"] = "open"
                elif sc in ("execve", "exec"):
                    data["type"] = "exec"
                elif sc in ("connect",):
                    data["type"] = "connect"
                else:
                    data["type"] = sc

            # Extract filename from details if not explicitly present
            if not data.get("filename") and data.get("details"):
                import re
                fn_match = re.search(r"filename=([^\s]+)", data["details"])
                if fn_match:
                    data["filename"] = fn_match.group(1)
                comm_match = re.search(r"comm=([^\s]+)", data["details"])
                if comm_match and not data.get("comm"):
                    data["comm"] = comm_match.group(1)

            event = KernelTelemetryEvent.model_validate(data)
            event_dict = event.model_dump()
        except ValidationError:
            with self.lock:
                self.stats["events_malformed"] += 1
            return

        with self.lock:
            self.stats["events_valid"] += 1
            self.events_buffer.append(event_dict)

    def get_events(
        self,
        pid: Optional[int] = None,
        time_window_sec: Optional[float] = None,
        since_timestamp: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Thread-safe retrieval of recent events filtered by PID and/or time window.
        """
        now = time.time()
        results = []

        with self.lock:
            events_snapshot = list(self.events_buffer)

        for ev in events_snapshot:
            # PID filter
            if pid is not None and ev.get("pid") != pid:
                continue

            # Timestamp filters
            ev_ts = ev.get("ts")
            if ev_ts is not None:
                if since_timestamp is not None and ev_ts < since_timestamp:
                    continue
                if time_window_sec is not None and (now - ev_ts) > time_window_sec:
                    continue

            results.append(ev)

        return results

    def correlate_agent_request(
        self,
        agent_request: Dict[str, Any],
        security_events: Optional[List[Dict[str, Any]]] = None,
        time_window_ms: float = 2000.0,
        target_worker_pid: Optional[int] = None
    ):
        """
        Directly evaluates an agent request against currently buffered live kernel events.
        Connects the receiver to the existing correlation, feature-extraction, and risk-scoring pipeline.
        """
        from detector.correlation.event_correlator import correlate_and_evaluate
        target_pid = target_worker_pid if target_worker_pid is not None else agent_request.get("pid")
        time_window_sec = (time_window_ms / 1000.0) if time_window_ms else None

        # Retrieve events matching the process within sliding window
        live_events = self.get_events(pid=target_pid, time_window_sec=time_window_sec)
        return correlate_and_evaluate(
            agent_request=agent_request,
            security_events=security_events or [],
            raw_kernel_events=live_events,
            time_window_ms=time_window_ms,
            target_worker_pid=target_worker_pid
        )

    def clear(self):
        """Clears the event ring buffer."""
        with self.lock:
            self.events_buffer.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Returns receiver performance and ingestion statistics."""
        with self.lock:
            st = dict(self.stats)
            st["current_buffer_length"] = len(self.events_buffer)
            st["port"] = self.port
            st["host"] = self.host
            st["running"] = self.is_running
            st["is_running"] = self.is_running
            return st
