
def analyze_logs(file_path):
    failed_attempts = {}

    login_counts = {
        "SUCCESS": 0,
        "FAILED": 0
    }

    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split(",")

                if len(parts) != 4:
                    continue

                ip_address = parts[2]
                status = parts[3]

                if status not in login_counts:
                    continue

                login_counts[status] += 1

                if status == "FAILED":
                    failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1

    except FileNotFoundError:
        print("Error: Log file not found:", file_path)

    return login_counts, failed_attempts

def detect_suspicious_ips(failed_attempts, threshold=3):
    suspicious_ips = {}

    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips


def generate_report(login_counts, failed_attempts, suspicious_ips, output_file):

    with open(output_file, "w") as report:

        report.write("SECURITY LOG ANALYSIS REPORT\n")
        report.write("============================\n\n")

        report.write("LOGIN SUMMARY\n")
        report.write(f"Successful Logins: {login_counts['SUCCESS']}\n")
        report.write(f"Failed Logins: {login_counts['FAILED']}\n\n")

        report.write("FAILED LOGIN ATTEMPTS BY IP\n")

        for ip, count in failed_attempts.items():
            report.write(f"{ip}: {count}\n")

        report.write("\nSUSPICIOUS IP ADDRESSES\n")

        for ip, count in suspicious_ips.items():
            report.write(f"{ip}: {count} failed attempts\n")


def main():
    file_path = "data/sample_auth.log"
    output_file = "reports/security_report.txt"

    login_counts, failed_attempts = analyze_logs(file_path)

    if not any(login_counts.values()):
        print("Analysis stopped: No valid login records found.")
        return

    suspicious_ips = detect_suspicious_ips(failed_attempts)

    print("Failed Login Attempts by IP Address")

    for ip, count in failed_attempts.items():
        print(ip, ":", count)

    print("\nSuspicious IP Addresses")

    for ip, count in suspicious_ips.items():
        print(ip, ":", count, "failed attempts")

    generate_report(
        login_counts,
        failed_attempts,
        suspicious_ips,
        output_file
    )

    print("\nSecurity report generated:", output_file)


if __name__ == "__main__":
    main()
