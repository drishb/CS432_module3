from flask import Blueprint, request, jsonify
from db_connection import get_db_connection
import hashlib

warden_bp = Blueprint('warden_bp', __name__)

@warden_bp.route('/addWarden', methods=['POST'])
def add_warden():
    data = request.get_json()

    name = data.get('name')
    contact = data.get('contact')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400

    username = email.split("@")[0]
    hashed_pw = hashlib.md5(password.encode()).hexdigest()

    try:
        conn = get_db_connection()
        conn.autocommit = False
        cursor = conn.cursor()

        # Insert into cs432cims.members
        cursor.execute("""
            INSERT INTO cs432cims.members (userName, emailID, DoB)
            VALUES (%s, %s, NULL)
        """, (username, email))
        member_id = cursor.lastrowid

        # Insert into Login
        cursor.execute("""
            INSERT INTO cs432cims.Login (MemberID, Password, Role)
            VALUES (%s, %s, 'warden')
        """, (member_id, hashed_pw))

        # Insert into your group’s warden table
        cursor.execute("""
            INSERT INTO cs432g4.warden (warden_id, name, contact, email)
            VALUES (%s, %s, %s, %s)
        """, (member_id, name, contact, email))

        conn.commit()
        return jsonify({"message": "Warden added", "member_id": member_id}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()
