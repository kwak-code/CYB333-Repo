#!/usr/bin/env python3
"""
client.py - Simple TCP client for CYB Midterm, Part 1.

Connects to server.py, sends messages typed by the user (or a single message
passed with --message), and prints the server's responses. Type 'quit' to
disconnect gracefully.

Usage:
    python client.py                          # interactive mode
    python client.py --message "Hello"        # send one message and exit
    python client.py --port 5000
"""

import argparse
import socket
import sys
from datetime import datetime

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 65432
BUFFER_SIZE = 1024
TIMEOUT_SECONDS = 5          # Don't hang forever if the server is unresponsive
ENCODING = "utf-8"


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    print(f"[{timestamp()}] [CLIENT] {message}", flush=True)


def send_and_receive(sock: socket.socket, message: str) -> str:
    """Send one message and return the server's decoded reply."""
    sock.sendall(message.encode(ENCODING))
    reply = sock.recv(BUFFER_SIZE)
    if not reply:
        raise ConnectionError("Server closed the connection")
    return reply.decode(ENCODING, errors="replace")


def run_client(host: str, port: int, single_message: str | None) -> int:
    """Connect to the server and exchange messages. Returns an exit code."""
    log(f"Attempting to connect to {host}:{port} ...")
    try:
        # create_connection resolves the host and applies the timeout
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
            log(f"Successfully connected to server at {host}:{port}")

            # One-shot mode: send a message, read the reply, then quit cleanly
            if single_message is not None:
                log(f"Sending: '{single_message}'")
                log(f"Server replied: {send_and_receive(sock, single_message)}")
                log(f"Server replied: {send_and_receive(sock, 'quit')}")
                log("Disconnected cleanly.")
                return 0

            # Interactive mode
            print("Type a message and press Enter. Type 'quit' to disconnect.")
            while True:
                try:
                    message = input("> ").strip()
                except EOFError:
                    message = "quit"   # Ctrl+D / end of input -> disconnect politely

                if not message:
                    continue  # Ignore empty lines

                reply = send_and_receive(sock, message)
                log(f"Server replied: {reply}")

                if message.lower() == "quit":
                    log("Disconnected cleanly.")
                    return 0

    except ConnectionRefusedError:
        log(f"ERROR: Connection refused. Is the server running on {host}:{port}?")
    except socket.timeout:
        log(f"ERROR: Connection to {host}:{port} timed out after {TIMEOUT_SECONDS}s")
    except socket.gaierror:
        log(f"ERROR: Could not resolve hostname '{host}'")
    except (ConnectionResetError, ConnectionError) as err:
        log(f"ERROR: Connection lost - {err}")
    except KeyboardInterrupt:
        print()
        log("Interrupted by user. Connection closed.")
        return 0
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port (default 65432)")
    parser.add_argument("--message", help="Send a single message and exit")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    return args


if __name__ == "__main__":
    a = parse_args()
    sys.exit(run_client(a.host, a.port, a.message))