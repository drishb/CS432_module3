from flask import Blueprint, request, jsonify, render_template
import mysql.connector
import hashlib
import jwt
import datetime
import logging
from db_connection import get_db_connection

visitor_signup_bp = Blueprint('visitor_signup_bp', __name__)

@visitor_signup_bp.route('/visitor-signup', methods=['GET', 'POST'])
def visitor_signup():
    if request.method == 'GET':
        return render_template('visitor_signup.html')
    
    elif request.method == 'POST':
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        # Extract fields
        visitor_name = data.get('name')
        student_id_field = data.get('studentID')
        email = data.get('email')
        password = data.get('password')
        contact = data.get('contact')
        in_time = data.get('in_time')
        out_time = data.get('out_time')
        role = "visitor"

        if not email or "@" not in email:
            return jsonify({"error": "Invalid or missing email address"}), 400
        if not visitor_name or not password or not student_id_field:
            return jsonify({"error": "Missing required fields"}), 400

        username = email.split("@")[0]

        try:
            conn = get_db_connection()
            conn.autocommit = False
            cursor = conn.cursor()

            # ✅ Check if username already exists in members table
            cursor.execute("SELECT 1 FROM cs432cims.members WHERE userName = %s", (username,))
            if cursor.fetchone():
                return jsonify({"error": f"Username '{username}' already exists in the database."}), 409

            # Step 1: Insert into cs432cims.members
            insert_members_sql = """
                INSERT INTO cs432cims.members (userName, emailID, DoB)
                VALUES (%s, %s, NULL)
            """
            cursor.execute(insert_members_sql, (username, email))
            member_id = cursor.lastrowid

            # Step 2: Insert into cs432cims.Login
            hashed_pw = hashlib.md5(password.encode()).hexdigest()
            insert_login_sql = """
                INSERT INTO cs432cims.Login (MemberID, Password, Role)
                VALUES (%s, %s, %s)
            """
            cursor.execute(insert_login_sql, (member_id, hashed_pw, role))

            # Step 3: Insert into cs432g4.visitors
            insert_visitors_sql = """
                INSERT INTO cs432g4.visitors (visitor_id, name, student_id, contact, in_time, out_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_visitors_sql, (member_id, visitor_name, student_id_field, contact, in_time, out_time))

            conn.commit()

            logging.info("CIMS Change: Visitor Signup - Created member (member_id: %s, email: %s, linked studentID: %s)",
                         member_id, email, student_id_field)

        except mysql.connector.Error as err:
            conn.rollback()
            return jsonify({"error": str(err)}), 500
        finally:
            cursor.close()
            conn.close()

        token = jwt.encode({
            "MemberID": member_id,
            "Role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, "CS432_SECRET", algorithm="HS256")

        return jsonify({
            "message": "Signup successful!",
            "member_id": member_id,
            "token": token
        }), 200
