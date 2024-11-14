#!/usr/bin/env python3
"""Handles API authentication for requests"""
from flask import request
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User
import base64


class BasicAuth(Auth):
    """Class for Basic Authentication"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extracts and returns the Base64 encoded part from the Authorization header"""
        if authorization_header is None or not isinstance(
                authorization_header, str):
            return None
        hd = authorization_header.split(' ')
        return hd[1] if hd[0] == 'Basic' else None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Splits and retrieves the user email and password from the decoded Base64 string"""
        if not decoded_base64_authorization_header or not isinstance(
                decoded_base64_authorization_header, str) or \
                ":" not in decoded_base64_authorization_header:
            return None, None
        extract = decoded_base64_authorization_header.split(':', 1)
        return extract[0], extract[1] if extract else (None, None)

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes a Base64 encoded string and returns the plain text"""
        if base64_authorization_header is None or not isinstance(
                base64_authorization_header, str):
            return None
        try:
            base64_bytes = base64_authorization_header.encode('utf-8')
            message_bytes = base64.b64decode(base64_bytes)
            return message_bytes.decode('utf-8')
        except Exception:
            return None

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Fetches the User instance that matches the provided email and password"""
        if not user_email or not isinstance(user_email, str) or \
                not user_pwd or not isinstance(user_pwd, str):
            return None
        users = User.search({'email': user_email})
        if not users:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Overrides Auth to find and return the User instance associated with the request"""
        try:
            header = self.authorization_header(request)
            base64_h = self.extract_base64_authorization_header(header)
            decode_h = self.decode_base64_authorization_header(base64_h)
            credents = self.extract_user_credentials(decode_h)
            return self.user_object_from_credentials(credents[0], credents[1])
        except Exception:
            return None
