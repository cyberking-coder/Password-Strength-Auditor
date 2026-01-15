# -------------------------------
# Task-01: Password Strength Auditor
# Developed using Python, Regex, and HaveIBeenPwned API
# -------------------------------

import re          # For regex-based validation
import hashlib     # For SHA-1 hashing
import requests    # For API requests


# Function to check password policy rules
def check_password_policy(password):
    """
    Checks password against security rules using regex
    Returns a dictionary of rule results
    """
    rules = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }
    return rules


# Function to check if password is breached using HaveIBeenPwned API
def hibp_check(password):
    """
    Uses k-Anonymity model to safely check password breach
    Returns number of times password was found in breaches
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


# Function to calculate password strength score
def calculate_score(rules, breach_count):
    """
    Calculates score based on rules and breach status
    """
    score = sum(rules.values()) * 20

    if breach_count > 0:
        score -= 40

    return max(score, 0)


# Main function to audit password
def audit_password(password):
    rules = check_password_policy(password)
    breach_count = hibp_check(password)
    score = calculate_score(rules, breach_count)

    print("\n🔐 PASSWORD AUDIT REPORT")
    print("-" * 30)

    for rule, passed in rules.items():
        print(f"{rule.capitalize():12}: {'✔' if passed else '✘'}")

    print(f"\nBreached Count : {breach_count}")
    print(f"Strength Score : {score}/100")

    if score >= 80:
        print("Status         : STRONG")
    elif score >= 50:
        print("Status         : MEDIUM")
    else:
        print("Status         : WEAK")


# User input
password = input("Enter password to audit: ")
audit_password(password)
