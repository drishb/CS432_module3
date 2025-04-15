from flask import Blueprint, request, jsonify, render_template
import mysql.connector
import hashlib
from db_connection import get_db_connection
import logging  # Make sure logging is imported

student_signup_bp = Blueprint('student_signup_bp', __name__)

@student_signup_bp.route('/student-signup', methods=['GET', 'POST'])
def student_signup():
    if request.method == 'GET':
        return render_template('student_signup.html')

    elif request.method == 'POST':
        data = request.get_json()

        # Retrieve data from the request payload
        full_name = data.get('Name')
        emailID = data.get('emailID')
        password = data.get('password')
        DoB = data.get('DoB')
        contact = data.get('contact')
        role = "student"
        age = data.get('age')
        room_id = data.get('Room_ID')
        hostel_id = data.get('Hostel_ID')

        if not emailID or "@" not in emailID:
            return jsonify({"error": "Invalid or missing email address"}), 400

        # Extract username from email for the members table
        username = emailID.split("@")[0]

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Begin a transaction
            conn.autocommit = False

            # Check if the username already exists in members
            cursor.execute("SELECT COUNT(*) FROM cs432cims.members WHERE userName = %s", (username,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"error": f"Username '{username}' already exists."}), 409

            # 1. Insert into cs432cims.members
            insert_members_sql = """
                INSERT INTO cs432cims.members (userName, emailID, DoB)
                VALUES (%s, %s, %s)
            """
            cursor.execute(insert_members_sql, (username, emailID, DoB))
            member_id = cursor.lastrowid

            # 2. Insert into cs432cims.Login with hashed password and role
            hashed_pw = hashlib.md5(password.encode()).hexdigest()
            insert_login_sql = """
                INSERT INTO cs432cims.Login (MemberID, Password, Role)
                VALUES (%s, %s, %s)
            """
            cursor.execute(insert_login_sql, (member_id, hashed_pw, role))

            check_room_sql = "SELECT 1 FROM cs432g4.room WHERE room_id = %s"
            cursor.execute(check_room_sql, (room_id,))
            if cursor.fetchone() is None:
                conn.rollback()
                return jsonify({"error": f"Room ID '{room_id}' does not exist. Please select a valid room."}), 400
            # 3. Insert into cs432g4.student
            insert_student_sql = """
                INSERT INTO cs432g4.student (name, age, email, contact_no, Room_ID, Hostel_ID)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_student_sql, (full_name, age, emailID, contact, room_id, hostel_id))

            # Commit all changes
            conn.commit()

            # Log the change to the centralized CIMS database
            logging.info("CIMS Change: Student Signup - Created member (member_id: %s, email: %s)", member_id, emailID)

        except mysql.connector.Error as err:
            conn.rollback()
            return jsonify({"error": str(err)}), 500

        finally:
            cursor.close()
            conn.close()

        # Return the new member ID to the client.
        return jsonify({
            "message": "Student signup successful!",
            "member_id": member_id
        }), 200
