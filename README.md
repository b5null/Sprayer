# Sprayer 🙏 – Kerberos AS-REQ Multi-Spray Tool

`Sprayer.py` is a Kerberos AS-REQ spraying toolkit built on top of [Impacket](https://github.com/fortra/impacket).  
It’s designed for **password / hash / AES key spraying against multiple users** in an Active Directory environment, supporting:

- Single user or userlist
- Passwords, NTLM hashes (`LMHASH:NTHASH` or `NTHASH`), and AES keys
- IPv4, IPv6, or hostname for the Domain Controller
- Controlled concurrency with a worker pool (threads)

---

## Features

- **User sources**
  - `-username` / `-userfile` (`user` or `DOMAIN/user` format)

- **Credential sources**
  - `-password` / `-passfile` (clear-text)
  - `-hashes` / `-hashfile` (NTLM hashes)
  - `-aesKey` / `-keysfile` (Kerberos AES keys – 128/256-bit hex)

- **Connection options**
  - `-dc-ip` – IPv4 (e.g. `10.0.0.10`) or IPv6 (e.g. `dead:beef::b885:d62a:d679:573f`)
  - `Hostname` – (e.g. `dc01.lab.local`)
  - `-domain` – AD FQDN (e.g. `lab.local`)

- **Safety & usability**
  - Worker pool with `-workers` to avoid resource exhaustion

- **Full combo mode**
  - Tries every **user × credential** combination:
    - user × passwords
    - user × hashes
    - user × AES keys
---

## Requirements
- Python 3.8+
- [Impacket](https://github.com/fortra/impacket) installed

Example installation:
```bash
pip install impacket
```
Or from source:
```bash
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .
```

---

## Usage
```bash
python3 Sprayer.py
usage: Sprayer.py [-h] [-username username] [-userfile userfile] [-password password] [-passfile passfile]
                  [-hashes LMHASH:NTHASH] [-hashfile hashfile] [-aesKey hex key] [-keysfile keysfile] [-domain domain]
                  [-dc-ip address] [-workers N]

Kerberos AS-REQ Spraying Toolkit (multi-user, multi-credential)

options:
  -h, --help            show this help message and exit

authentication:
  -username username    Single username to spray (use [domain/]username or just username)
  -userfile userfile    File with usernames, one per line, optionally in [domain/]username format
  -password password    Single clear-text password
  -passfile passfile    File with clear-text passwords, one per line
  -hashes LMHASH:NTHASH
                        Single NTLM hash, format LMHASH:NTHASH
  -hashfile hashfile    File with hashes, one per line in LMHASH:NTHASH or NTHASH format
  -aesKey hex key       Single AES key (hex) for Kerberos Authentication (128 or 256 bits)
  -keysfile keysfile    File with AES keys (hex), one per line

connection:
  -domain domain        FQDN of the target domain
  -dc-ip address        Domain controller address (hostname, IPv4, or IPv6)
  -workers N            Number of concurrent worker processes (default: 10)
```


- **1. Single user + hashfile**
```bash
python3 Sprayer.py \
  -username john.doe \
  -hashfile hashes.txt \
  -domain corp.local \
  -dc-ip 'dead:beef::b885:d62a:d679:a4f2'
```


- **2. Userlist + password list**
```bash
python3 Sprayer.py \
  -userfile users.txt \
  -passfile passwords.txt \
  -domain corp.local \
  -dc-ip 10.0.0.10 \
  -workers 20
```

- **3. Userlist + aesKeys file**
python3 Sprayer.py \
  -userfile users.txt \
  -keysfile aes_keys.txt \
  -domain lab.local \
  -dc-ip dc01.lab.local

---

## Notes & OPSEC
This tool sends Kerberos AS-REQs and may:
 - Trigger account lockouts if thresholds are low.
 - Generate logs on DCs and security monitoring systems.
 - Always coordinate with the blue team / SOC during engagements.
 - Tune -workers to match engagement rules and lab conditions.

---

## ⚠️Disclaimer
For educational and authorized testing only. Use only with explicit permission. The authors assume no liability for misuse.
Do not use it against systems you do not own or have explicit permission to test.

---

## Author

- :skull: **B5null**
