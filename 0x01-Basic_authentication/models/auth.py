#!/usr/bin/env python3
"""Main authentication module"""

from flask import request
from typing import List, TypeVar

class Auth:
    """Primary authentication class to manage access control and user validation."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if a given path requires authentication.

        Args:
            path (str): Path of the current request.
            excluded_paths (List[str]): Paths that bypass authentication.

        Returns:
            bool: Returns True if path requires authentication, False otherwise.
        """
        # Return True if path is None
        if path is None:
            return True

        # Return True if excluded_paths is None or empty
        if not excluded_paths:
            return True

        # Ensure path ends with a trailing slash for consistent comparison
        normalized_path = path if path.endswith('/') else path + '/'

        # Check if the normalized path matches any of the excluded paths
        for excluded_path in excluded_paths:
            if excluded_path.endswith('/'):
                if normalized_path == excluded_path:
                    return False
            elif path == excluded_path or path == excluded_path + '/':
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Fetches the authorization header from a request object.

        Args:
            request: Flask request object containing request headers.

        Returns:
            str: Returns the authorization header as a string, or None if absent.
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Identifies the current user associated with the provided request.

        Args:
            request: The Flask request object to extract user information.

        Returns:
            TypeVar('User'): Represents the current user or None if not identified.
        """
        return None

