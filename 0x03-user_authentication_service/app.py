#!/usr/bin/env python3

"""Module defining routes for the API."""

from db import DB
from flask import Flask, jsonify, request, abort, redirect
from flask.helpers import make_response
from auth import Auth
from user import User

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def welcome() -> str:
    """Root endpoint for the API.
    Returns:
        A welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_users():
    """Endpoint to register new users.
    JSON payload:
        - email: User's email address.
        - password: User's password.
    Returns:
        A confirmation message or an error if the email is already registered.
    """
    user_request = request.form
    try:
        user = AUTH.register_user(
            user_request['email'],
            user_request['password'])
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """Endpoint for user login.
    JSON payload:
        - email: User's email address.
        - password: User's password.
    Returns:
        A response with a session cookie if credentials are valid.
    """
    user_request = request.form

    user_email = user_request.get('email', '')
    user_password = user_request.get('password', '')
    valid_log = AUTH.valid_login(user_email, user_password)
    if not valid_log:
        abort(401)
    response = make_response(
        jsonify({"email": user_email, "message": "logged in"}))
    response.set_cookie('session_id', AUTH.create_session(user_email))
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """Endpoint to log out users.
    Uses session cookies to find the user.
    Returns:
        Redirects to the root endpoint after logging out.
    """
    user_cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(user_cookie)
    if user_cookie is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Retrieve user profile using the session ID.
    Returns:
        The email address of the logged-in user or 403 if invalid.
    """
    user_cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(user_cookie)
    if user_cookie is None or user is None:
        abort(403)
    return jsonify({"email": user}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token_route() -> str:
    """Request a reset token for password recovery.
    JSON payload:
        - email: The user's email.
    Returns:
        A reset token or 403 if the email is unregistered.
    """
    user_request = request.form
    user_email = user_request.get('email', '')
    is_registered = AUTH.create_session(user_email)

    if not is_registered:
        abort(403)

    token = AUTH.get_reset_password_token(user_email)
    return jsonify({"email": user_email, "reset_token": token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Update the user's password using a reset token.
    JSON payload:
        - email: The user's email.
        - reset_token: The password reset token.
        - new_password: The new password to set.
    Returns:
        A success message or 403 if the token is invalid.
    """
    user_email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, new_password)
    except Exception:
        abort(403)

    return jsonify(
        {"email": user_email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
