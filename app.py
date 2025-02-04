from flask import Flask,jsonify,request
from werkzeug.security import generate_password_hash,check_password_hash
from pymongo import MongoClient, errors
from pymongo.errors import DuplicateKeyError
from werkzeug.exceptions import BadRequest
import smtplib
import string
import secrets
import os
from flask_cors import CORS




app = Flask(__name__)
uri = "mongodb+srv://pandukrishna04:Raina%40143@cluster0.4fkpx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db=client.get_database('Health')
Doctor_collection=db['Doctor']
Student_collection = db['Student']
PendingStudent_collection = db['PendingStudent']
CORS(app)


Doctor_collection.create_index("email", unique=True)
Doctor_collection.create_index("doctorId", unique=True)

PendingStudent_collection.create_index("email", unique=True)
PendingStudent_collection.create_index("studentId", unique=True)
Student_collection.create_index("email", unique=True)
Student_collection.create_index("studentId", unique=True)


def generate_admin_credentials():
    """Generate admin username and password."""
    username = "admin"
    password = "admin123"  # Use the same password generation function
    hashed_password = generate_password_hash(password)

    # Store credentials in environment variables or a secure location
    os.environ['ADMIN_USERNAME'] = username
    os.environ['ADMIN_PASSWORD'] = hashed_password

    # For demonstration purposes, print the credentials
    print(f"Admin credentials - Username: {username}, Password: {password}")


generate_admin_credentials()


def generate_password(length=12):
    """Generates a random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))



def send_email(recipient, email, password):

    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    message = f"""Subject: Your Login Details

    Dear Doctor,

    Your account has been created. Here are your login details:

    Email: {email}
    Password: {password}

    Best regards,
    HealthCare Team
    """

    # Send the email
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, message)



@app.route('/admin_login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Check credentials
        stored_username = os.environ.get('ADMIN_USERNAME')
        stored_password = os.environ.get('ADMIN_PASSWORD')

        if username == stored_username and check_password_hash(stored_password, password):
            return jsonify({"message": "Admin login successful"}), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except Exception as e:
        return jsonify({"error": f"An error occurred during login: {str(e)}"}), 500





@app.route('/register', methods=['POST'])
def register_doctor():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Validate input data
        name = data.get('name')
        email = data.get('email')
        mobile = data.get('mobile')
        doctorId = data.get('doctorId')
        designation = data.get('designation')
        placeOfWork = data.get('placeOfWork')

        if not all([name, email, mobile, doctorId, designation, placeOfWork]):
            return jsonify({"error": "Missing required fields"}), 400

        if Doctor_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400
        if Doctor_collection.find_one({"doctorId": doctorId}):
            return jsonify({"error": "Doctor ID already registered."}), 400



        # Generate a random password
        password = generate_password()

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new doctor document
        doctor = {
            "name": name,
            "email": email,
            "mobile": mobile,
            "doctorId": doctorId,
            "designation": designation,
            "placeOfWork": placeOfWork,
            "password": hashed_password
        }

        # Send email with login details
        send_email(email, email, password)

        # Insert the doctor into the collection
        Doctor_collection.insert_one(doctor)

        return jsonify({"message": "Doctor registered successfully! Login details sent to email."}), 201


    except Exception as e:
        return jsonify({"error": "An error occurred during registration."}), 500






@app.route('/register_student', methods=['POST'])
def register_student():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Validate input data
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone')
        studentId = data.get('studentId')
        college = data.get('college')
        degree = data.get('degree')

        if not all([name, email, phone, studentId, college, degree]):
            return jsonify({"error": "Missing required fields"}), 400

        # Check for existing email or studentId in pending and approved collections
        if PendingStudent_collection.find_one({"email": email}) or Student_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400
        if PendingStudent_collection.find_one({"studentId": studentId}) or Student_collection.find_one({"studentId": studentId}):
            return jsonify({"error": "Student ID already registered."}), 400

        # Generate a random password
        password = generate_password()

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new pending student document
        pending_student = {
            "name": name,
            "email": email,
            "phone": phone,
            "studentId": studentId,
            "college": college,
            "degree": degree,
            "password": hashed_password, # Store hashed password
            "plain_password": password
        }

        # Insert the student into the pending collection
        PendingStudent_collection.insert_one(pending_student)

        return jsonify({"message": "Student registered successfully! Awaiting approval."}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred during registration: {str(e)}"}), 500


def send_student_email(recipient, email, password):
    """Send an email with student login details."""
    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    message = f"""Subject: Your Student Login Details

    Dear Student,

    Your account has been approved. Here are your login details:

    Email: {email}
    Password: {password}

    Best regards,
    HealthCare Team
    """

    # Send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, message)

@app.route('/approve_student', methods=['PUT'])
def approve_student():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        studentId = data.get('studentId')
        if not studentId:
            return jsonify({"error": "Student ID is required"}), 400

        # Check if the student is in the approved collection
        if Student_collection.find_one({"studentId": studentId}):
            return jsonify({"error": "Student already approved"}), 400

        # Find the student in the pending collection
        pending_student = PendingStudent_collection.find_one({"studentId": studentId})
        if not pending_student:
            return jsonify({"error": "Student not found in pending approvals"}), 404

        # Move the student to the approved collection
        Student_collection.insert_one(pending_student)
        PendingStudent_collection.delete_one({"studentId": studentId})

        # Send email with login details
        send_student_email(pending_student['email'], pending_student['email'], pending_student['plain_password'])

        return jsonify({"message": "Student approved successfully!"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred during approval: {str(e)}"}), 500


@app.route('/reject_student', methods=['PUT'])
def reject_student():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        studentId = data.get('studentId')
        if not studentId:
            return jsonify({"error": "Student ID is required"}), 400

        # Find the student in the pending collection
        pending_student = PendingStudent_collection.find_one({"studentId": studentId})
        if not pending_student:
            return jsonify({"error": "Student not found in pending approvals"}), 404

        # Remove the student from the pending collection
        PendingStudent_collection.delete_one({"studentId": studentId})

        # Optionally, send an email to the student about the rejection
        send_rejection_email(pending_student['email'], pending_student['name'])

        return jsonify({"message": "Student registration rejected successfully."}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred during rejection: {str(e)}"}), 500
def send_rejection_email(recipient, name):
    """Send an email notifying the student of rejection."""
    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    message = f"""Subject: Registration Rejection Notice

    Dear {name},

    We regret to inform you that your registration has been rejected.

    Best regards,
    HealthCare Team
    """

    # Send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, message)

if __name__ == '__main__':
    app.run(debug=True)



