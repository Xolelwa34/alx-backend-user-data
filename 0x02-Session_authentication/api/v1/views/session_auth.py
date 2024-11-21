#!/usr/bin/env python3
"""
Defines routes for session-based authentication.
"""

from flask import jsonify, request, abort, make_response
from api.v1.views import app_views
from models.user import User
import os
from api.v1.auth.session_auth import SessionAuth


# Initialize the session authentication object
auth = SessionAuth()

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_auth_login():
    """
    Handles POST /auth_session/login for session-based authentication.
    Retrieves the email and password from the request form,
    and performs authentication, returning the user data if successful.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if email or password is missing
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Find user by email
    users = User.search({"email": email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create session ID for user and set it in a cookie
    session_id = auth.create_session(user.id)

    response = jsonify(user.to_json())
    session_name = os.getenv("SESSION_NAME", "_my_session_id")  # Use the default session name if not set
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_auth_logout():
    """
    Handles DELETE /auth_session/logout to log out the user by destroying their session.
    """
    if not auth.destroy_session(request):
        abort(404)  # If no session exists or failed to destroy, return 404
    
    return jsonify({}), 200  # Return an empty JSON response with status 200


@app_views.route('/users/me', methods=['GET'], strict_slashes=False)
def get_user_info():
    """
    Retrieves the current user information based on the session cookie.
    """
    session_id = auth.session_cookie(request)
    if session_id is None:
        abort(404)  # If no session cookie, return 404
    user_id = auth.user_id_for_session_id(session_id)
    if user_id is None:
        abort(404)  # If no user linked to the session, return 404

    # Retrieve user and return their data
    user = User.get(user_id)
    if user is None:
        abort(404)  # If user does not exist, return 404

    return jsonify(user.to_json())
