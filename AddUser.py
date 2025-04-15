from flask import Blueprint, request, jsonify
import hashlib
from db_connection import get_db_connection

add_user_bp = Blueprint('add_user_bp', __name__)  # create a Flask blueprint

@add_user_bp.route('/addUser', methods=['POST'])
def add_user_route():
    data = request.get_json()
    required_fields = ['UserName', 'emailID', 'DoB', 'Role']
    if not all(k in data for k in required_fields):
        return jsonify({"error": "Missing fields"}), 400

    username = data['UserName']
    email = data['emailID']
    dob = data['DoB']
    role = data['Role']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Step 1: Insert into members
        cursor.execute(
            "INSERT INTO members (UserName, emailID, DoB) VALUES (%s, %s, %s)",
            (username, email, dob)
        )
        member_id = cursor.lastrowid

        # Step 2: Insert into Login table with hashed password
        default_password = hashlib.md5(username.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO Login (MemberID, Password, Session, Expiry, Role) VALUES (%s, %s, '', NULL, %s)",
            (member_id, default_password, role)
        )

        conn.commit()
        return jsonify({"message": f"Member '{username}' created with ID {member_id} and login initialized."}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()
