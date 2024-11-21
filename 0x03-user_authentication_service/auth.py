#!/usr/bin/env python3
"""
Authentication module.
"""
from db import DB
import bcrypt
from user import User


class Auth:
    """Auth class for authentication management."""

    def __init__(self):
        """Initialize Auth with a database instance."""
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash a password."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def register_user(self, email: str, password: str) -> User:
        """Register a new user."""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = self._hash_password(password)
            return self._db.add_user(email=email, hashed_password=hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate login credentials."""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(), user.hashed_password.encode())
        except (NoResultFound, AttributeError):
            return False
