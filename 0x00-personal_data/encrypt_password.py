#!/usr/bin/env python3
"""main bycript"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password with a salt using bcrypt.
    Returns a hashed password in byte form.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a provided password matches the hashed password.
    Returns True if they match, False otherwise.
    """
    # Check if the password matches the hashed password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
