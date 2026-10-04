"""Generate a TOTP secret + QR code for two-step login (2FA).

Usage:
    python setup_2fa.py

Then:
    1. Copy the printed TOTP_SECRET=... line into your .env file.
    2. Scan 2fa-qr.png with Google Authenticator / Authy / 1Password
       (or enter the base32 key manually).
    3. Restart the web app.
"""

import pyotp
import qrcode


def main() -> None:
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name="nmap-scanner", issuer_name="Nmap Scanner"
    )
    qrcode.make(uri).save("2fa-qr.png")

    print("=" * 60)
    print("Two-step verification setup")
    print("=" * 60)
    print()
    print("1. Add this line to your .env file:")
    print()
    print(f"   TOTP_SECRET={secret}")
    print()
    print("2. Scan 2fa-qr.png with your authenticator app")
    print("   (or enter the key above manually):")
    print("      - Google Authenticator (Android / iOS)")
    print("      - Authy (Android / iOS)")
    print("      - 1Password / Bitwarden / Raft OTP")
    print()
    print(f"3. Current code for a quick test: {pyotp.TOTP(secret).now()}")
    print()
    print("4. Restart the web app.")
    print()
    print("IMPORTANT: keep the secret safe. If you lose it, remove")
    print("TOTP_SECRET from .env to fall back to access-code-only login.")


if __name__ == "__main__":
    main()
