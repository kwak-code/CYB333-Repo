#!/usr/bin/env python3
"""
server.py - Simple TCP echo/response server for CYB Midterm, Part 1.

The server binds to a host/port, listens for a client, receives messages,
prints them with a timestamp, and sends back an acknowledgment. The client
can type 'quit' to disconnect cleanly. Press Ctrl+C to shut the server down.

Usage:
    python server.py                  # defaults to 127.0.0.1:65432
    python server.py --port 5000
"""

import argparse
import socket
import sys
from datetime import datetime

DEFAULT_HOST = "127.0.0.1"   # Loopback only - not exposed to the network
DEFAULT_PORT = 65432         # Unprivileged port (> 1023), no admin rights needed
BUFFER_SIZE = 1024           # Max bytes read per recv() call
ENCODING = "utf-8"


def timestamp() -> str:
    """Return the current time as a readable string for log output."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    """Print a timestamped log line (timestamps help verify screenshots)."""
    print(f"[{timestamp()}] [SERVER] {message}", flush=True)


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Exchange messages with one connected client until it disconnects."""
    log(f"Connection established with {addr[0]}:{addr[1]}")
    with conn:  # Context manager guarantees the client socket is closed
        while True:
            data = conn.recv(BUFFER_SIZE)

            # recv() returning b"" means the client closed its side
            if not data:
                log(f"Client {addr[0]}:{addr[1]} closed the connection")
                break

            message = data.decode(ENCODING, errors="replace").strip()
            log(f"Received from client: '{message}'")

            if message.lower() == "quit":
                conn.sendall("Goodbye! Closing connection.".encode(ENCODING))
                log("Client requested disconnect - closing connection gracefully")
                break

            # Build and send a response so the client can confirm receipt
            response = f"Server received your message: '{message}' at {timestamp()}"
            conn.sendall(response.encode(ENCODING))
            log("Response sent to client")


def run_server(host: str, port: int) -> None:
    """Create, bind, and run the listening socket."""
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        # Allow quick restarts without "Address already in use" errors
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((host, port))
        except OSError as err:
            log(f"ERROR: Could not bind to {host}:{port} - {err}")
            sys.exit(1)

        server_sock.listen(1)  # Backlog of 1 pending connection is enough here
        log(f"Server started. Listening on {host}:{port} (Ctrl+C to stop)")

        while True:
            try:
                conn, addr = server_sock.accept()  # Blocks until a client connects
                handle_client(conn, addr)
                log("Waiting for the next connection...")
            except ConnectionResetError:
                log("WARNING: Client disconnected unexpectedly (connection reset)")
            except KeyboardInterrupt:
                raise  # Let the outer handler perform the shutdown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Address to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on (default 65432)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    try:
        run_server(arguments.host, arguments.port)
    except KeyboardInterrupt:
        print()  # Move past the ^C on the terminal
        log("Shutdown requested (Ctrl+C). Server socket closed. Goodbye.")
        sys.exit(0)
