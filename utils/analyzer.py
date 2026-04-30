import re
import math
import bcrypt
import sqlite3


# some common weak passwords
COMMON_PASSWORDS = ["123456", "password", "qwerty", "abc123"]


def get_entropy(password):
    """Calculate entropy based on character variety"""

    pool_size = 0

    if re.search(r'[a-z]', password):
        pool_size += 26

    if re.search(r'[A-Z]', password):
        pool_size += 26

    if re.search(r'[0-9]', password):
        pool_size += 10

    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32

    if pool_size == 0:
        return 0

    return len(password) * math.log2(pool_size)


def analyze_password(password):
    """Check strength + entropy"""

    # check if it's a very common password
    if password.lower() in COMMON_PASSWORDS:
        return {
            "strength": "Weak",
            "entropy": 0
        }

    entropy = get_entropy(password)

    if entropy < 40:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    else:
        strength = "Strong"

    return {
        "strength": strength,
        "entropy": entropy
    }


def estimate_crack_time(entropy):
    """Rough estimate of crack time"""

    if entropy < 40:
        return "Seconds"
    elif entropy < 60:
        return "Hours to Days"
    else:
        return "Years"


def is_reused_password(password):
    """Check if password was already used"""

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # create table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            hash TEXT
        )
    """)

    cursor.execute("SELECT hash FROM passwords")
    saved_hashes = cursor.fetchall()

    for row in saved_hashes:
        stored_hash = row[0].encode()

        if bcrypt.checkpw(password.encode(), stored_hash):
            conn.close()
            return True

    # store new password hash
    hashed_pwd = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute(
        "INSERT INTO passwords (hash) VALUES (?)",
        (hashed_pwd.decode(),)
    )

    conn.commit()
    conn.close()

    return False