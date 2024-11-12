#!/usr/bin/env python3
"""Main authentication module"""

from flask import request
from typing import List, TypeVar

class Auth:
    """Primary class to manage authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is needed for a specific path.

        Args:
            path (str): The path of the current request.
            excluded_paths (List[str]): 
            List of paths exempted from requiring authentication.

        Returns:
            bool: True if authentication is needed, otherwise False.
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        Gets the authorization header from a request.

        Args:
            request: The Flask request object.

        Returns:
            str: The authorization header as a string, or None if unavailable.
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Identifies the user associated with the given request.

        Args:
            request: The Flask request object.

        Returns:
            TypeVar('User'): The current user, or None if not applicable.
        """
        return None

