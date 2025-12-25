import ipaddress
from collections import Counter

def load_suspicious_ranges(path="suspicious_ranges.txt"):
    ranges = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ranges.append(ipaddress.ip_network(line))
    except FileNotFoundError:
        pass
    return ranges

def is_in_suspicious_range(ip, ranges):
    return any(ip in net for net in ranges)

def analyze_ips(ip_list, suspicious_ranges):
    results = []
    counts = Counter(ip_list)

    for ip_str in ip_list:
        ip = ipaddress.ip_address(ip_str)
        score = 0
        reasons = []

        if ip.is_private:
            reasons.append("Private IP address")
        else:
            score += 1

        if is_in_suspicious_range(ip, suspicious_ranges):
            score += 2
            reasons.append("IP in suspicious network range")

        if counts[ip_str] > 3:
            score += 2
            reasons.append("Repeated IP occurrence (possible scanning)")

        if score >= 4:
            risk = "HIGH"
        elif score >= 2:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        results.append({
            "ip": ip_str,
            "risk": risk,
            "reasons": reasons
        })

    return results

def main():
    suspicious_ranges = load_suspicious_ranges()

    print("=== Suspicious IP Reputation Checker ===")
    ip_input = input("Enter IPs separated by commas: ")
    ip_list = [ip.strip() for ip in ip_input.split(",")]

    results = analyze_ips(ip_list, suspicious_ranges)

    print("\nResults:")
    for r in results:
        print(f"\nIP: {r['ip']}")
        print(f"Risk Level: {r['risk']}")
        if r["reasons"]:
            print("Reasons:")
            for reason in r["reasons"]:
                print(f"- {reason}")
        else:
            print("No suspicious indicators detected.")

if __name__ == "__main__":
    main()