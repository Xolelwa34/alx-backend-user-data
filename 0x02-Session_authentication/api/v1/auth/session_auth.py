#!/usr/bin/env python3
"""
Implements session-based authentication for a Flask application.
"""

from flask import Flask, request, abort
import os
import uuid


class Auth:
    """
    Base authentication class with session cookie retrieval capabilities.
    """

    def session_cookie(self, request=None):
        """
        Retrieves the session cookie from a given request.
        The cookie name is defined by the SESSION_NAME environment variable.
        """
        if request is None:
            return None
        session_name = os.getenv("SESSION_NAME", "_my_session_id")
        return request.cookies.get(session_name)


class SessionAuth(Auth):
    """
    Manages session-based authentication by assigning and tracking session IDs.
    """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Generates a session ID for a specified user ID.
        Returns the session ID, or None if the user ID is invalid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Finds the user ID associated with a given session ID.
        Returns None if the session ID is invalid or does not exist.
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)


# Setting up the Flask application
app = Flask(__name__)
auth = SessionAuth()


@app.before_request
def before_request():
    """
    Executed before each request.
    Verifies the presence of a session cookie or authorization header.
    """
    excluded_paths = ["/api/v1/auth_session/login/", "/api/v1/status"]
    if request.path not in excluded_paths:
        if auth.authorization_header(request) is None and \
                auth.session_cookie(request) is None:
            abort(401)


@app.route('/', methods=['GET'], strict_slashes=False)
def root_path():
    """
    Root route to display the current session cookie for debugging.
    """
    return "Cookie value: {}\n".format(auth.session_cookie(request))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("API_PORT", 5000)))
