# CYB Midterm – Socket Connection & Port Scanner

Python 3.10+ (standard library only, nothing to install).

| File | Purpose |
|---|---|
| `server.py` | TCP server that listens on 127.0.0.1:65432, logs messages, and sends responses |
| `client.py` | TCP client that connects, sends messages, and disconnects cleanly with `quit` |
| `port_scanner.py` | TCP connect scanner limited to localhost and scanme.nmap.org |

## Part 1 – Socket test sequence (screenshot each step)

Use two terminal windows side by side, and keep the system clock visible in each screenshot.

1. **Error handling, server not running:** `python client.py` → "Connection refused. Is the server running?"
2. **Start the server:** `python server.py` → "Listening on 127.0.0.1:65432"
3. **Connect:** `python client.py` in the second terminal → "Successfully connected"
4. **Message exchange:** type `Hello server` → the server logs "Received from client", and the client prints "Server replied"
5. **Graceful disconnect:** type `quit` → both sides log the clean close
6. **Server shutdown:** press Ctrl+C in the server window → "Shutdown requested... Goodbye"

## Part 2 – Port scanner test sequence

To get an open port on localhost, start a test web server in another terminal: `python -m http.server 8000`

| Test case | Command |
|---|---|
| Common ports on localhost | `python port_scanner.py 127.0.0.1 --common` |
| Custom range (shows 8000 open) | `python port_scanner.py 127.0.0.1 --range 7990-8010` |
| Selected ports on scanme.nmap.org | `python port_scanner.py scanme.nmap.org --ports 22,80,443,9929,31337` |
| Invalid port number | `python port_scanner.py 127.0.0.1 --ports 80,99999` |
| Invalid range | `python port_scanner.py 127.0.0.1 --range 100-50` |
| Non-numeric port | `python port_scanner.py 127.0.0.1 --ports abc` |
| Unauthorized target (refused) | `python port_scanner.py google.com --common` |
| Unreachable host | Turn Wi-Fi off, then run `python port_scanner.py scanme.nmap.org --ports 22,80` |
| Performance | Compare elapsed time for `--range 1-100` vs `--range 1-1000` on localhost |

Add `--open-only` to hide closed ports on large ranges.

## Ethical safeguards built into the scanner
- A hard-coded allowlist of targets (127.0.0.1, localhost, scanme.nmap.org); any other target is refused
- Rate limiting: a delay between attempts, with a minimum of 0.2 s for scanme.nmap.org
- A cap of 100 ports per scan against scanme.nmap.org
- Plain TCP connect scans only: no SYN, stealth, or flood techniques
