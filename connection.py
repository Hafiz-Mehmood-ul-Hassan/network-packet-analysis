import subprocess
from dataclasses import dataclass
from typing import List

def list_interfaces():
    """
    Prints all available network interfaces detected by tshark -D.
    """
    proc = subprocess.Popen(
        ["tshark", "-D"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    output = proc.communicate()[0]

    print("Available Network Interfaces:\n")
    for line in output.splitlines():
        start,end=line.find("("),line.find(")")
        if line[start+1:end] == "Wi-Fi":
            # print(line[0],line[start+1:end])
            return line[0]




# 1) This class represents ONE connection handshake as a Python object
# @dataclass
# class Connection:
#     src_ip: str      # client IP (your machine)
#     src_port: int    # client port
#     dst_ip: str      # server IP (Facebook, etc.)
#     dst_port: int    # server port (usually 443)
#     hostname: str    # SNI hostname (e.g. www.facebook.com)


# # 2) This function runs forever, reads handshakes, and stores them in a list
# def capture_tls_handshakes(interface: str) -> List[Connection]:
#     """
#     Continuously listen for TLS ClientHello (handshakes) on given interface,
#     and keep a list of Connection objects for each handshake.
#     """

#     # This list will store all connection objects we see
#     connections: List[Connection] = []

#     # Build the tshark command that will run in the background
#     tshark_cmd = [
#         "tshark",
#         "-l",                      # line-buffered output (so we see lines immediately)
#         "-i", interface,           # which network interface to listen on
#         "-Y", "tls.handshake.type == 1",  # only TLS ClientHello (start of TLS handshake)
#         "-T", "fields",            # print only selected fields
#         "-e", "ip.src",            # source IP
#         "-e", "tcp.srcport",       # source TCP port
#         "-e", "ip.dst",            # destination IP
#         "-e", "tcp.dstport",       # destination TCP port
#         "-e", "tls.handshake.extensions_server_name"  # SNI hostname
#     ]

#     # Start tshark as a subprocess so we can read its output line by line
#     proc = subprocess.Popen(
#         tshark_cmd,
#         stdout=subprocess.PIPE,     # we want to read its output in Python
#         stderr=subprocess.DEVNULL,  # ignore tshark errors in this example
#         text=True,                  # read text (str), not bytes
#         bufsize=1                   # line-buffered
#     )

#     print("Listening for TLS handshakes (ClientHello) on interface:", interface)

#     try:
#         # Infinite loop: keep reading as long as tshark is running
#         while True:
#             line = proc.stdout.readline()
#             if not line:
#                 # tshark ended or no more data
#                 break

#             line = line.strip()
#             if not line:
#                 # empty line, skip it
#                 continue

#             # tshark prints: src_ip src_port dst_ip dst_port hostname
#             parts = line.split()

#             # We need at least src_ip, src_port, dst_ip, dst_port
#             if len(parts) < 4:
#                 continue

#             src_ip = parts[0]
#             src_port_str = parts[1]
#             dst_ip = parts[2]
#             dst_port_str = parts[3]
#             hostname = parts[4] if len(parts) >= 5 else ""

#             # Convert port strings to integer safely
#             try:
#                 src_port = int(src_port_str)
#                 dst_port = int(dst_port_str)
#             except ValueError:
#                 # If ports are not valid integers, skip this line
#                 continue
#             # check if the host name is facebook.com
#             if hostname == "gateway.facebook.com" or hostname == "static.xx.fbcdn.net":
                    

#                 # # Create a Connection object for this handshake
#                 # conn = Connection(
#                 #     src_ip=src_ip,
#                 #     src_port=src_port,
#                 #     dst_ip=dst_ip,
#                 #     dst_port=dst_port,
#                 #     hostname=hostname
#                 # )

#                 # # Add it to our list
#                 # connections.append(conn)

#                 # For now, just print it so you can see it working
#                 print(f"[HANDSHAKE] {src_ip}:{src_port} -> {dst_ip}:{dst_port} host={hostname}")

#             # Later you can:
#             #  - push this object into a "active connections" structure
#             #  - start parallel processing per connection
#             #  - filter only facebook/insta/twitter/linkedin by hostname

#     finally:
#         # If something goes wrong or loop stops, make sure to stop tshark
#         proc.terminate()

#     # In this design the loop is "infinite", so normally this return is never reached.
#     # If you break the loop, this will give you all captured connections.
#     return connections

import subprocess
import threading
from dataclasses import dataclass
from typing import List, Tuple


# --- Connection object ---

@dataclass
class Connection:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    hostname: str

    def key(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """
        Normalized key so that (A:port1 -> B:port2) and (B:port2 -> A:port1)
        are considered the same connection.
        """
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        return (a, b) if a <= b else (b, a)


def make_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    a = (ip1, port1)
    b = (ip2, port2)
    return (a, b) if a <= b else (b, a)


# --- Worker 1: add connections on TLS handshake (your original logic) ---

def handshake_worker(interface: str, active_connections: List[Connection], lock: threading.Lock):
    """
    Continuously listen for TLS ClientHello (handshakes) on given interface,
    and add Facebook-related connections to active_connections.
    """

    tshark_cmd = [
        "tshark",
        "-l",
        "-i", interface,
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tls.handshake.extensions_server_name"
    ]

    proc = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("[HANDSHAKE] Listening on:", interface)

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            src_ip = parts[0]
            src_port_str = parts[1]
            dst_ip = parts[2]
            dst_port_str = parts[3]
            hostname = parts[4] if len(parts) >= 5 else ""

            try:
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)
            except ValueError:
                continue

            # your Facebook-only filter
            if hostname not in ("gateway.facebook.com", "static.xx.fbcdn.net"):
                continue

            conn = Connection(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                hostname=hostname
            )
            conn_key = conn.key()

            # Add only if not already in list
            with lock:
                exists = any(c.key() == conn_key for c in active_connections)
                if not exists:
                    active_connections.append(conn)
                    print(f"[NEW] {src_ip}:{src_port} -> {dst_ip}:{dst_port} host={hostname}")
                    print(f"       Active connections: {len(active_connections)}")
    finally:
        proc.terminate()
        print("[HANDSHAKE] Worker stopped")


# --- Worker 2: remove connections when TCP FIN/RST seen ---

def end_worker(interface: str, active_connections: List[Connection], lock: threading.Lock):
    """
    Continuously listen for TCP FIN/RST packets and remove matching connections
    from active_connections.
    """

    tshark_cmd = [
        "tshark",
        "-l",
        "-i", interface,
        "-Y", "tcp.flags.fin==1 or tcp.flags.reset==1",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport"
    ]

    proc = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("[END] Listening for FIN/RST on:", interface)

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            src_ip = parts[0]
            src_port_str = parts[1]
            dst_ip = parts[2]
            dst_port_str = parts[3]

            try:
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)
            except ValueError:
                continue

            end_key = make_key(src_ip, src_port, dst_ip, dst_port)

            with lock:
                before = len(active_connections)
                active_connections[:] = [
                    c for c in active_connections if c.key() != end_key
                ]
                after = len(active_connections)

                if before != after:
                    print(f"[END] Closed: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
                    print(f"      Active connections: {after}")
    finally:
        proc.terminate()
        print("[END] Worker stopped")


# --- Simple runner example ---

def main():
    interface = "Wi-Fi"   # change to your interface, or plug in your auto-detect here

    active_connections: List[Connection] = []
    lock = threading.Lock()

    t_add = threading.Thread(
        target=handshake_worker,
        args=(interface, active_connections, lock),
        daemon=True
    )
    t_end = threading.Thread(
        target=end_worker,
        args=(interface, active_connections, lock),
        daemon=True
    )

    t_add.start()
    t_end.start()

    print("[MAIN] Running. Press Ctrl+C to stop.")
    try:
        while True:
            # here you could also iterate over active_connections and do your tasks
            pass
    except KeyboardInterrupt:
        print("\n[MAIN] Stopping...")



if __name__ == "__main__":
    # interface=list_interfaces()
    # print(interface)
    # capture_tls_handshakes(interface)
    main()










