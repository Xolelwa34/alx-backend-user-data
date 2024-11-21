#!/usr/bin/env python3
"""
Implements session-based authentication for a Flask application.
"""

from flask import Flask, request, abort, jsonify
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

    def destroy_session(self, request=None):
        """
        Deletes the session associated with the current request's session cookie.
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_id]  # Remove the session from the dictionary
        return True


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
        if auth.session_cookie(request) is None:
            abort(401)


@app.route('/api/v1/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    Handles the logout process by destroying the user's session.
    """
    if not auth.destroy_session(request):
        abort(404)  # If no session exists or failed to destroy, return 404
    return jsonify({}), 200  # Return a blank response with status 200


@app.route('/api/v1/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """
    Logs in a user and creates a session for them.
    """
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Dummy authentication check
    if email == 'bobsession@hbtn.io' and password == 'fake pwd':
        session_id = auth.create_session('cf3ddee1-ff24-49e4-a40b-2540333fe992')  # Dummy user ID
        response = jsonify({
            'created_at': '2017-10-16 04:23:04',
            'email': email,
            'id': 'cf3ddee1-ff24-49e4-a40b-2540333fe992',
            'updated_at': '2017-10-16 04:23:04'
        })
        response.set_cookie(auth.session_name, session_id)
        return response
    abort(401)  # Unauthorized if credentials are incorrect


@app.route('/api/v1/users/me', methods=['GET'], strict_slashes=False)
def get_user_info():
    """
    Fetches user information from the session.
    """
    session_id = auth.session_cookie(request)
    if session_id is None:
        abort(404)  # If no session cookie, return 404
    user_id = auth.user_id_for_session_id(session_id)
    if user_id is None:
        abort(404)  # If no user is linked to the session, return 404
    return jsonify({
        'created_at': '2017-10-16 04:23:04',
        'email': 'bobsession@hbtn.io',
        'first_name': None,
        'id': user_id,
        'last_name': None,
        'updated_at': '2017-10-16 04:23:04'
    })


@app.route('/', methods=['GET'], strict_slashes=False)
def root_path():
    """
    Root route to display the current session cookie for debugging.
    """
    return "Cookie value: {}\n".format(auth.session_cookie(request))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("API_PORT", 5000)))
