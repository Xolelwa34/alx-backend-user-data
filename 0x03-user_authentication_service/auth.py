#!/usr/bin/env python3

"""Auth class for handling user authentication and validation."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from db import DB
from user import User
import bcrypt
import uuid


def _hash_password(password: str) -> str:
    """Generates a salted hash of the given password."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Creates a unique UUID and returns it as a string."""
    return str(uuid.uuid4())


class Auth:
    """A class for interacting with the database for authentication operations."""

    def __init__(self):
        """Initializes the Auth class with an instance of the database."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user.
        Args:
            email: The user's email address.
            password: The user's password.
        Returns:
            The newly created user object.
        Raises:
            ValueError: If the email is already in use.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists.".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's credentials.
        Args:
            email: The user's email.
            password: The plain text password.
        Returns:
            True if the login credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> str:
        """Creates a new session for a user.
        Args:
            email: The user's email.
        Returns:
            The generated session ID, or None if the user is not found.
        """
        session_id = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """Finds the user associated with a session ID.
        Args:
            session_id: The session ID to look up.
        Returns:
            The email of the user, or None if not found.
        """
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user.email
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Ends a user's session.
        Args:
            user_id: The ID of the user whose session is being terminated.
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset token for password recovery.
        Args:
            email: The user's email address.
        Returns:
            The generated reset token.
        Raises:
            ValueError: If the user does not exist.
        """
        updated_token = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, reset_token=updated_token)
            return updated_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using a reset token.
        Args:
            reset_token: The reset token provided to the user.
            password: The new password to set.
        Raises:
            ValueError: If the reset token is invalid or not found.
        """
        if reset_token is None or password is None:
            return None

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(user.id,
                             hashed_password=hashed_password,
                             reset_token=None)
