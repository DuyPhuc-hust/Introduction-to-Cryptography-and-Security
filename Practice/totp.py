import hmac
import hashlib
import time


def generate_totp(secret_key, current_timestamp):
    # 1. Calculate time counter
    time_counter = current_timestamp // 30

    # 2. Convert to bytes
    msg = str(time_counter).encode("utf-8")
    key = secret_key.encode("utf-8")

    # 3. Compute HMAC-SHA256
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()

    # 4. Take last 8 hex characters
    last_8_hex = digest[-8:]

    # 5. Convert hex to integer
    value = int(last_8_hex, 16)

    # 6. Modulo and zero-pad
    otp = str(value % 1_000_000).zfill(6)

    return otp


def verify_totp(secret_key, user_token, current_timestamp):
    expected_token = generate_totp(secret_key, current_timestamp)
    return expected_token == user_token

# Test Case 1: Manual Check
SECRET_KEY = "STUDENT_ID_SECRET"
TIMESTAMP = 1700000000

otp = generate_totp(SECRET_KEY, TIMESTAMP)
print("Test Case 1 OTP:", otp)  # Expected: 924761

# Test Case 2: Live System Check
LIVE_KEY = "MY_KEY"

current_time = int(time.time())
token = generate_totp(LIVE_KEY, current_time)

if verify_totp(LIVE_KEY, token, current_time):
    print("Live Test (Immediate): PASS")
else:
    print("Live Test (Immediate): FAIL")

time.sleep(5)

new_time = int(time.time())
if verify_totp(LIVE_KEY, token, new_time):
    print("Live Test (After 5s): PASS")
else:
    print("Live Test (After 5s): FAIL")
