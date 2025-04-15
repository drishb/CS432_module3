from flask import Flask, render_template, redirect, url_for, request, jsonify, g
import mysql.connector
import hashlib
import jwt
import datetime
import logging  # new import
from auth import auth_required
from db_connection import get_db_connection
from AddUser import add_user_bp
from flask_cors import CORS
from StudentSignup import student_signup_bp
from VisitorSignup import visitor_signup_bp
from WardenAPI import warden_bp
from datetime import datetime, timedelta, timezone



# Configure logging: prints to console and writes to server.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log")
    ]
)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'CS432_SECRET'  # Replace with an environment variable in production

app.register_blueprint(add_user_bp)
app.register_blueprint(student_signup_bp)
app.register_blueprint(visitor_signup_bp)
app.register_blueprint(warden_bp)


# ------------------ Authentication Routes ------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/select_role')
def select_role():
    return render_template('select_role.html')

@app.route('/student_login')
def student_login():
    return render_template('student_login.html')

@app.route('/warden_login')
def warden_login():
    return render_template('warden_login.html')

@app.route('/visitor_login')
def visitor_login():
    return render_template('visitor_login.html')

@app.route('/student_signup')
def student_signup():
    return render_template('student_signup.html')

@app.route('/visitor_signup')
def visitor_signup():
    return render_template('visitor_signup.html')

@app.route('/dashboardStudent')
@auth_required(app)
def dashboard_student():
    # Assuming your auth decorator sets g.member_id after verifying the token
    return render_template("dashboardStudent.html", member_id=g.member_id)

@app.route('/visitor-dashboard')
@auth_required(app)
def visitor_dashboard():
    member_id = g.member_id

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cs432g4.visitors WHERE visitor_id = %s", (member_id,))
    visitor_data = cursor.fetchone()

    cursor.close()
    conn.close()

    if visitor_data:
        return render_template("dashboardVisitor.html", visitor=visitor_data)
    else:
        return render_template("dashboardVisitor.html", error="No visitor record found.")

@app.route('/warden-dashboard')
@auth_required(app)
def warden_dashboard():
    member_id = g.member_id

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cs432g4.warden WHERE warden_id = %s", (member_id,))
    warden_data = cursor.fetchone()
    cursor.close()
    conn.close()

    if not warden_data:
        return render_template("warden_dashboard.html", warden={ "warden_id": member_id, "name": "N/A", "contact": "-", "email": "-", "hostel_name": "-" })

    # add placeholder if hostel_name isn't in table
    warden_data.setdefault("hostel_name", "Not Assigned")
    return render_template("warden_dashboard.html", warden=warden_data)

@app.route('/add_room')
def add_room():
    return render_template("add_room.html")

@app.route('/add_item')
def add_item():
    return render_template("add_item.html")

@app.route('/delete_item')
def delete_item():
    return render_template("delete_item.html")

@app.route('/manage_inventory')
@auth_required(app)
def manage_inventory():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT item_id, item_name, quantity, i_condition FROM cs432g4.inventory ORDER BY item_id ASC")
    items = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("manage_inventory.html", items=items)

@app.route('/view_complaints')
@auth_required(app)
def view_complaints():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT complaint_no, Student_ID, category, status, complaint_date FROM cs432g4.complaints ORDER BY complaint_date DESC")
    complaints = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("view_complaints.html", complaints=complaints)




@app.route('/logout')
def logout():
    resp = redirect(url_for('warden_login'))
    resp.delete_cookie('token')  # deletes JWT token
    return resp


@app.route('/authUser', methods=['POST'])
def auth_user():
    # Accept either JSON or form data.
    data = request.get_json() if request.is_json else request.form

    member_id = data.get('MemberID')
    password = data.get('Password')
    role_sent = data.get('Role')  # Make sure the login form sends a hidden field Role = "student"
    
    if not member_id or not password:
        return jsonify({"error": "Missing MemberID or Password"}), 400

    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM Login WHERE MemberID = %s", (member_id,))
    user = cursor.fetchone()

    if user and user['Password'] == hashed_pw:
        # Role validation: ensure that the role coming in matches the user role in the database
        if user['Role'] != role_sent:
            cursor.close()
            conn.close()
            return jsonify({"error": "Unauthorized role login"}), 403

        # Generate token
        token = jwt.encode({
    "MemberID": member_id,
    "Role": user["Role"],
    "exp": datetime.now(timezone.utc) + timedelta(hours=1)
}, app.config['SECRET_KEY'], algorithm="HS256")

        expiry_time = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
 

        cursor.execute("UPDATE Login SET Session = %s, Expiry = %s WHERE MemberID = %s",
                       (token, expiry_time, member_id))
        conn.commit()
        cursor.close()
        conn.close()

        # Instead of returning JSON, redirect to the student dashboard.
        # Set the token in a cookie for subsequent use.
        # Role-based redirection
        if user['Role'] == 'student':
            response = redirect(url_for("dashboard_student"))
        elif user['Role'] == 'visitor':
            response = redirect(url_for("visitor_dashboard"))

        elif user['Role'] == 'warden':
            response = redirect(url_for("warden_dashboard"))

        elif user['Role'] == 'admin':
            response = redirect(url_for("admin_dashboard"))

        else:
            return jsonify({"error": "Unknown role"}), 403
        response.set_cookie("token", token)
        return response


    else:
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

# ------------------ Example Route (Token Check) ------------------
@app.route('/example', methods=['GET'])
@auth_required(app)
def example():
    return jsonify({"message": f"Hello {g.member_id}, your role is {g.role}."})

@app.route('/assignGroup', methods=['POST'])
@auth_required(app)
def assign_group():
    data = request.json
    member_id = data.get('MemberID')
    group_id = data.get('GroupID')

    if not member_id or not group_id:
        return jsonify({"error": "MemberID and GroupID required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if MemberID exists
    cursor.execute("SELECT 1 FROM members WHERE ID = %s", (member_id,))
    if cursor.fetchone() is None:
        cursor.close()
        conn.close()
        return jsonify({"error": f"Member {member_id} does not exist"}), 404

    # Proceed to insert into mapping
    cursor.execute("INSERT INTO MemberGroupMapping (MemberID, GroupID) VALUES (%s, %s)",
                   (member_id, group_id))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": f"Member {member_id} assigned to group {group_id}."}), 200

# ------------------ Member Deletion Routes ------------------
@app.route('/member/<int:member_id>', methods=['GET'])
@auth_required(app)
def check_member(member_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM members WHERE ID = %s", (member_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return jsonify({"member": result}), 200
    else:
        return jsonify({"message": f"Member {member_id} not found."}), 404

@app.route('/deleteMember/<member_id>', methods=['DELETE'])
@auth_required(app)
def delete_member(member_id):
    group_name = 'cs432g4'  # your group name
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check how many groups this member is in
    cursor.execute("SELECT COUNT(*) FROM MemberGroupMapping WHERE MemberID = %s", (member_id,))
    count = cursor.fetchone()[0]

    if count > 1:
        # Just remove the mapping for cs432g4
        cursor.execute("DELETE FROM MemberGroupMapping WHERE MemberID = %s AND GroupName = %s", (member_id, group_name))
        msg = f"Removed group mapping for {group_name}, member still exists in other groups."
    else:
        # Fully delete member from all relevant tables
        cursor.execute("DELETE FROM MemberGroupMapping WHERE MemberID = %s", (member_id,))
        cursor.execute("DELETE FROM Login WHERE MemberID = %s", (member_id,))
        cursor.execute("DELETE FROM members WHERE ID = %s", (member_id,))
        msg = f"Member {member_id} fully deleted."

    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": msg}), 200

# ------------------ Run App ------------------
if __name__ == '__main__':
    app.run(debug=True)
