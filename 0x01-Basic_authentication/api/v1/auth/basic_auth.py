#!/usr/bin/env python3
"""Primary module for basic authentication handling"""

from api.v1.auth.auth import Auth
import base64

class BasicAuth(Auth):
    """Class to handle Basic Authentication methods"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Isolates the Base64 encoded portion from a Basic Authorization header.

        Args:
            authorization_header (str): The Authorization header string from the request.

        Returns:
            str: The Base64 encoded credentials part, or None if invalid.
        """
        if authorization_header is None or not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64 encoded authorization header.

        Args:
            base64_authorization_header (str): The encoded Base64 string.

        Returns:
            str: The decoded string in UTF-8, or None if decoding fails.
        """
        if base64_authorization_header is None or not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Parses and retrieves the user email and password from a decoded authorization header.

        Args:
            decoded_base64_authorization_header (str): Decoded authorization string in the format "email:password".

        Returns:
            tuple: A tuple (email, password) if valid, otherwise (None, None).
        """
        if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        return decoded_base64_authorization_header.split(':', 1)

