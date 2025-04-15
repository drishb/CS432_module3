from functools import wraps
from flask import request, jsonify, g
import jwt

def auth_required(app):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Retrieve the token from the cookies.
            token = request.cookies.get("token")
            if not token:
                return jsonify({"error": "Missing or invalid token"}), 401
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                g.member_id = payload.get("MemberID")
                g.role = payload.get("Role")
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Missing or invalid token"}), 401
            return f(*args, **kwargs)
        return wrapped
    return decorator
