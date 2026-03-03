#!/usr/bin/env python3
"""
cert-watch - Monitor SSL certificate expiration dates for multiple domains.
"""

import argparse
import json
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Optional


DEFAULT_WARNING_DAYS = 30
DEFAULT_CRITICAL_DAYS = 7
DEFAULT_CONFIG_FILE = "~/.cert-watch.json"


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    expanded_path = os.path.expanduser(config_path)
    if not os.path.exists(expanded_path):
        return {"domains": [], "warning_days": DEFAULT_WARNING_DAYS, "critical_days": DEFAULT_CRITICAL_DAYS}
    
    try:
        with open(expanded_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing config file: {e}", file=sys.stderr)
        return {"domains": [], "warning_days": DEFAULT_WARNING_DAYS, "critical_days": DEFAULT_CRITICAL_DAYS}


def save_config(config: dict, config_path: str) -> bool:
    """Save configuration to JSON file."""
    expanded_path = os.path.expanduser(config_path)
    try:
        os.makedirs(os.path.dirname(expanded_path), exist_ok=True)
        with open(expanded_path, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except IOError as e:
        print(f"Error saving config: {e}", file=sys.stderr)
        return False


def get_certificate_info(hostname: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """Fetch SSL certificate information from a remote host."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
                
                if not cert:
                    return None
                
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                
                not_before = not_before.replace(tzinfo=timezone.utc)
                not_after = not_after.replace(tzinfo=timezone.utc)
                
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                
                return {
                    "hostname": hostname,
                    "subject": subject.get("commonName", hostname),
                    "issuer": issuer.get("commonName", "Unknown"),
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial_number": cert.get("serialNumber", "Unknown"),
                    "version": cert.get("version", "Unknown"),
                    "success": True,
                    "error": None
                }
                
    except socket.gaierror as e:
        return {
            "hostname": hostname,
            "success": False,
            "error": f"DNS resolution failed: {e}"
        }
    except socket.timeout:
        return {
            "hostname": hostname,
            "success": False,
            "error": "Connection timed out"
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname,
            "success": False,
            "error": f"Certificate verification failed: {e}"
        }
    except ssl.SSLError as e:
        return {
            "hostname": hostname,
            "success": False,
            "error": f"SSL error: {e}"
        }
    except ConnectionRefusedError:
        return {
            "hostname": hostname,
            "success": False,
            "error": "Connection refused"
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "success": False,
            "error": str(e)
        }


def check_expiration(cert_info: dict, warning_days: int, critical_days: int) -> tuple:
    """Check certificate expiration status and return status level and message."""
    if not cert_info["success"]:
        return "error", cert_info["error"]
    
    now = datetime.now(timezone.utc)
    days_until_expiry = (cert_info["not_after"] - now).days
    
    if days_until_expiry < 0:
        return "expired", f"EXPIRED {abs(days_until_expiry)} days ago"
    elif days_until_expiry <= critical_days:
        return "critical", f"{days_until_expiry} days remaining (CRITICAL)"
    elif days_until_expiry <= warning_days:
        return "warning", f"{days_until_expiry} days remaining (WARNING)"
    else:
        return "ok", f"{days_until_expiry} days remaining"


def format_date(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.RED = ""
        cls.MAGENTA = ""
        cls.CYAN = ""


def colorize(text: str, color: str) -> str:
    """Wrap text with ANSI color codes."""
    return f"{color}{text}{Colors.RESET}"


def print_single_report(cert_info: dict, warning_days: int, critical_days: int, verbose: bool = False):
    """Print detailed report for a single certificate."""
    if not cert_info["success"]:
        print(f"\n{colorize('[ERROR]', Colors.RED)} {cert_info['hostname']}")
        print(f"  Reason: {cert_info['error']}")
        return

    status, message = check_expiration(cert_info, warning_days, critical_days)

    status_colors = {
        "ok": Colors.GREEN,
        "warning": Colors.YELLOW,
        "critical": Colors.RED,
        "expired": Colors.RED,
        "error": Colors.MAGENTA
    }

    status_icons = {
        "ok": "✓",
        "warning": "⚠",
        "critical": "✗",
        "expired": "✗",
        "error": "?"
    }

    icon = status_icons.get(status, "?")
    color = status_colors.get(status, Colors.RESET)

    print(f"\n{colorize(icon, color)} {cert_info['hostname']}")
    print(f"  Status: {colorize(message, color)}")
    print(f"  Subject: {cert_info['subject']}")
    print(f"  Issuer: {cert_info['issuer']}")
    print(f"  Valid From: {format_date(cert_info['not_before'])}")
    print(f"  Valid Until: {format_date(cert_info['not_after'])}")
    print(f"  Serial: {cert_info['serial_number']}")
    print(f"  Version: {cert_info['version']}")


def print_summary_report(results: list, warning_days: int, critical_days: int):
    """Print summary report for multiple certificates."""
    if not results:
        print("No certificates to display.")
        return

    status_counts = {"ok": 0, "warning": 0, "critical": 0, "expired": 0, "error": 0}

    status_colors = {
        "ok": Colors.GREEN,
        "warning": Colors.YELLOW,
        "critical": Colors.RED,
        "expired": Colors.RED,
        "error": Colors.MAGENTA
    }

    print("\n" + "=" * 80)
    print(f"{Colors.BOLD}CERTIFICATE STATUS SUMMARY{Colors.RESET}")
    print("=" * 80)
    print(f"{'Domain':<40} {'Status':<15} {'Expires In':<20}")
    print("-" * 80)

    for cert_info in results:
        if cert_info["success"]:
            status, message = check_expiration(cert_info, warning_days, critical_days)
            status_counts[status] = status_counts.get(status, 0) + 1

            now = datetime.now(timezone.utc)
            days_left = (cert_info["not_after"] - now).days

            if status == "expired":
                status_str = "EXPIRED"
                expiry_str = f"{abs(days_left)} days ago"
            else:
                status_str = status.upper()
                expiry_str = f"{days_left} days"
        else:
            status = "error"
            status_counts["error"] = status_counts.get("error", 0) + 1
            status_str = "ERROR"
            expiry_str = cert_info["error"][:20]

        color = status_colors.get(status, Colors.RESET)
        domain = cert_info["hostname"][:38]
        colored_status = colorize(status_str, color)
        print(f"{domain:<40} {colored_status:<15} {expiry_str:<20}")

    print("-" * 80)
    summary_text = (
        f"Summary: OK={status_counts['ok']}, Warning={status_counts['warning']}, "
        f"Critical={status_counts['critical']}, Expired={status_counts['expired']}, "
        f"Errors={status_counts['error']}"
    )
    print(colorize(summary_text, Colors.BOLD))
    print("=" * 80 + "\n")


def add_domain(config: dict, hostname: str, config_path: str) -> bool:
    """Add a domain to the configuration."""
    if hostname not in config["domains"]:
        config["domains"].append(hostname)
        return save_config(config, config_path)
    return True


def remove_domain(config: dict, hostname: str, config_path: str) -> bool:
    """Remove a domain from the configuration."""
    if hostname in config["domains"]:
        config["domains"].remove(hostname)
        return save_config(config, config_path)
    return True


def list_domains(config: dict):
    """List all configured domains."""
    if not config["domains"]:
        print("No domains configured.")
        return
    
    print("Configured domains:")
    for domain in config["domains"]:
        print(f"  - {domain}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor SSL certificate expiration dates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s -c check example.com other.com
  %(prog)s --add example.com
  %(prog)s --list
  %(prog)s --watch
        """
    )
    
    parser.add_argument("domains", nargs="*", help="Domains to check")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE,
                        help=f"Config file path (default: {DEFAULT_CONFIG_FILE})")
    parser.add_argument("-w", "--warning", type=int, default=DEFAULT_WARNING_DAYS,
                        help=f"Warning threshold in days (default: {DEFAULT_WARNING_DAYS})")
    parser.add_argument("-e", "--critical", type=int, default=DEFAULT_CRITICAL_DAYS,
                        help=f"Critical threshold in days (default: {DEFAULT_CRITICAL_DAYS})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed certificate information")
    parser.add_argument("--add", metavar="DOMAIN", help="Add domain to config")
    parser.add_argument("--remove", metavar="DOMAIN", help="Remove domain from config")
    parser.add_argument("--list", action="store_true", help="List configured domains")
    parser.add_argument("--watch", action="store_true",
                        help="Watch configured domains for expiration")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    args = parser.parse_args()

    # Disable colors if output is not a TTY
    if not sys.stdout.isatty():
        Colors.disable()

    config = load_config(args.config)
    
    if args.warning:
        config["warning_days"] = args.warning
    if args.critical:
        config["critical_days"] = args.critical
    
    if args.add:
        if add_domain(config, args.add, args.config):
            print(f"Added {args.add} to configuration")
        else:
            print(f"Failed to add {args.add}", file=sys.stderr)
            sys.exit(1)
        return
    
    if args.remove:
        if remove_domain(config, args.remove, args.config):
            print(f"Removed {args.remove} from configuration")
        else:
            print(f"Failed to remove {args.remove}", file=sys.stderr)
            sys.exit(1)
        return
    
    if args.list:
        list_domains(config)
        return
    
    domains_to_check = list(args.domains)
    
    if args.watch or (not domains_to_check and config["domains"]):
        domains_to_check.extend(config["domains"])
    
    if not domains_to_check:
        parser.print_help()
        sys.exit(0)
    
    domains_to_check = list(set(domains_to_check))
    
    results = []
    for domain in domains_to_check:
        hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
        cert_info = get_certificate_info(hostname)
        results.append(cert_info)
        
        if args.verbose and not args.json:
            print_single_report(cert_info, config["warning_days"], config["critical_days"])
    
    if args.json:
        output = []
        for cert_info in results:
            if cert_info["success"]:
                status, message = check_expiration(
                    cert_info, config["warning_days"], config["critical_days"]
                )
                now = datetime.now(timezone.utc)
                days_left = (cert_info["not_after"] - now).days
                output.append({
                    "hostname": cert_info["hostname"],
                    "status": status,
                    "days_remaining": days_left,
                    "expires": cert_info["not_after"].isoformat(),
                    "issuer": cert_info["issuer"]
                })
            else:
                output.append({
                    "hostname": cert_info["hostname"],
                    "status": "error",
                    "error": cert_info["error"]
                })
        print(json.dumps(output, indent=2))
    elif not args.verbose:
        print_summary_report(results, config["warning_days"], config["critical_days"])
    
    has_issues = any(
        not r["success"] or check_expiration(r, config["warning_days"], config["critical_days"])[0] 
        in ["critical", "expired", "error"]
        for r in results if r
    )
    
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
