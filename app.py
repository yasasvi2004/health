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
import random







app = Flask(__name__)
uri = "mongodb+srv://pandukrishna04:Raina%40143@cluster0.4fkpx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db=client.get_database('Health')
Doctor_collection=db['Doctor']
Student_collection = db['Student']
PendingPatients_collection = db['PendingPatients']
ApprovedPatients_collection = db['ApprovedPatients']
CORS(app)


Doctor_collection.create_index("email", unique=True)
Doctor_collection.create_index("doctorId", unique=True)


Student_collection.create_index("email", unique=True)
Student_collection.create_index("studentId", unique=True)


def generate_admin_credentials():
    """Generate admin username and password."""
    username = "admin@1"
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
            "usertype": "doctor",
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

        # Check for existing email or studentId in the approved collection
        if Student_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400
        if Student_collection.find_one({"studentId": studentId}):
            return jsonify({"error": "Student ID already registered."}), 400

        # Generate a random password
        password = generate_password()

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new student document
        student = {
            "name": name,
            "email": email,
            "phone": phone,
            "studentId": studentId,
            "college": college,
            "degree": degree,
            "usertype": "student",
            "password": hashed_password  # Store hashed password
        }

        # Insert the student into the collection
        Student_collection.insert_one(student)

        # Send email with login details
        send_student_email(email, email, password)

        return jsonify({"message": "Student registered successfully! Login details sent to email."}), 201

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

    Your account has been created. Here are your login details:

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




















@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        email = data.get('email')
        password = data.get('password')

        # Check if the user is an admin
        stored_username = os.environ.get('ADMIN_USERNAME')
        stored_password = os.environ.get('ADMIN_PASSWORD')
        if email == stored_username and check_password_hash(stored_password, password):
            return jsonify({
                "message": "Login successful",
                "user": {
                    "username": stored_username,
                    "usertype": "admin"
                }
            }), 200

        # Check if the user is a doctor
        doctor = Doctor_collection.find_one({"email": email})
        if doctor and check_password_hash(doctor['password'], password):
            return jsonify({
                "message": "Login successful",
                "user": {
                    "name": doctor['name'],
                    "email": doctor['email'],
                    "mobile": doctor['mobile'],
                    "doctorId": doctor['doctorId'],
                    "designation": doctor['designation'],
                    "placeOfWork": doctor['placeOfWork'],
                    "usertype": "doctor"
                }
            }), 200

        # Check if the user is a student
        student = Student_collection.find_one({"email": email})
        if student and check_password_hash(student['password'], password):
            return jsonify({
                "message": "Login successful",
                "user": {
                    "name": student['name'],
                    "email": student['email'],
                    "phone": student['phone'],
                    "studentId": student['studentId'],
                    "college": student['college'],
                    "degree": student['degree'],
                    "usertype": "student"
                }
            }), 200

        # If no match is found
        return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        return jsonify({"error": f"An error occurred during login: {str(e)}"}), 500

@app.route('/submit_patient', methods=['POST'])
def submit_patient():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Validate input data
        patientName = data.get('patientName')
        patientEmail = data.get('patientEmail')
        clinicalCondition = data.get('clinicalCondition')
        studentName = data.get('name')
        studentId = data.get('studentId')

        if not all([patientName, patientEmail, clinicalCondition, studentName, studentId]):
            return jsonify({"error": "Missing required fields"}), 400

        # Create a new pending patient document
        pending_patient = {
            "patientName": patientName,
            "patientEmail": patientEmail,
            "clinicalCondition": clinicalCondition,
            "submittedBy": {
                "name": studentName,
                "studentId": studentId
            }
        }

        # Insert the patient into the pending collection
        PendingPatients_collection.insert_one(pending_patient)

        return jsonify({"message": "Patient details submitted successfully! Awaiting doctor approval."}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred during submission: {str(e)}"}), 500


@app.route('/pending_patients', methods=['GET'])
def get_pending_patients():
    try:
        # Retrieve all pending patients
        pending_patients = list(PendingPatients_collection.find({}, {'_id': 0}))

        return jsonify({"pending_patients": pending_patients}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred while fetching pending patients: {str(e)}"}), 500

@app.route('/approve_patient', methods=['PUT'])
def approve_patient():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        patientEmail = data.get('patientEmail')
        if not patientEmail:
            return jsonify({"error": "Patient email is required"}), 400

        # Find the patient in the pending collection
        pending_patient = PendingPatients_collection.find_one({"patientEmail": patientEmail})
        if not pending_patient:
            return jsonify({"error": "Patient not found in pending approvals"}), 404

        # Update patient details with any new information provided
        updated_patient = {
            "patientName": data.get('patientName', pending_patient['patientName']),
            "patientEmail": patientEmail,  # Email is used as the identifier, so it remains unchanged
            "clinicalCondition": data.get('clinicalCondition', pending_patient['clinicalCondition']),
            "submittedBy": pending_patient['submittedBy']  # Keep the original submitter's info
        }

        # Move the updated patient to the approved collection
        ApprovedPatients_collection.insert_one(updated_patient)
        PendingPatients_collection.delete_one({"patientEmail": patientEmail})

        return jsonify({"message": "Patient approved and updated successfully!"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred during approval: {str(e)}"}), 500


@app.route('/reject_patient', methods=['PUT'])
def reject_patient():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        patientEmail = data.get('patientEmail')
        if not patientEmail:
            return jsonify({"error": "Patient email is required"}), 400

        # Find the patient in the pending collection
        pending_patient = PendingPatients_collection.find_one({"patientEmail": patientEmail})
        if not pending_patient:
            return jsonify({"error": "Patient not found in pending approvals"}), 404

        # Remove the patient from the pending collection
        PendingPatients_collection.delete_one({"patientEmail": patientEmail})

        # Optionally, send a notification to the student about the rejection
        student_info = pending_patient['submittedBy']

        return jsonify({"message": "Patient rejected successfully."}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred during rejection: {str(e)}"}), 500




def send_reset_email(recipient, usertype):
    """Send an email notifying the user of a successful password reset."""
    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    message = f"""Subject: Password Reset Confirmation

    Dear {usertype},

    Your password has been successfully reset.

    If you did not request this change, please contact support immediately.

    Best regards,
    HealthCare Team
    """

    # Send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, message)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        email = data.get('email')
        old_password = data.get('oldPassword')
        new_password = data.get('newPassword')

        if not all([email, old_password, new_password]):
            return jsonify({"error": "Missing required fields"}), 400

        # Check if the user is a doctor
        user = Doctor_collection.find_one({"email": email})
        if user and check_password_hash(user['password'], old_password):
            # Check if the new password is different from the old password
            if old_password == new_password:
                return jsonify({"error": "New password must be different from the old password."}), 400

            # Update to new password
            new_hashed_password = generate_password_hash(new_password)
            Doctor_collection.update_one(
                {"email": email},
                {"$set": {"password": new_hashed_password}}
            )
            send_reset_email(email, "Doctor")
            return jsonify({"message": "Password reset successfully for doctor."}), 200

        # Check if the user is a student
        user = Student_collection.find_one({"email": email})
        if user and check_password_hash(user['password'], old_password):
            # Check if the new password is different from the old password
            if old_password == new_password:
                return jsonify({"error": "New password must be different from the old password."}), 400

            # Update to new password
            new_hashed_password = generate_password_hash(new_password)
            Student_collection.update_one(
                {"email": email},
                {"$set": {"password": new_hashed_password}}
            )
            send_reset_email(email, "Student")
            return jsonify({"message": "Password reset successfully for student."}), 200

        # If no match or incorrect old password
        return jsonify({"error": "Invalid email or password."}), 401

    except Exception as e:
        return jsonify({"error": f"An error occurred during password reset: {str(e)}"}), 500




def generate_otp():
    return str(random.randint(100000, 999999))

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')  # User email to send OTP

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Check if the user is a doctor
    user = Doctor_collection.find_one({"email": email})
    if not user:
        # Check if the user is a student
        user = Student_collection.find_one({"email": email})
        if not user:
            return jsonify({"error": "User with this email not found"}), 404

    # Generate and save OTP
    otp = generate_otp()
    # Save OTP in the user's document (you might want to add an 'otp' field to your user documents)
    if 'usertype' in user and user['usertype'] == 'doctor':
        Doctor_collection.update_one({"email": email}, {"$set": {"otp": otp}})
    else:
        Student_collection.update_one({"email": email}, {"$set": {"otp": otp}})

    # Send OTP via email using smtplib
    try:
        sender_email = "vutukuridinesh18@gmail.com"
        sender_password = "krvz zgas bqsu ymuh"
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        message = f"""Subject: Password Reset OTP

        Dear User,

        Your OTP for password reset is: {otp}

        If you did not request this, please contact support immediately.

        Best regards,
        HealthCare Team
        """

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message)
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

    return jsonify({"message": "OTP sent successfully"}), 200


@app.route('/reset-password-with-otp', methods=['POST'])
def reset_password_with_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('newPassword')

    if not all([email, otp, new_password]):
        return jsonify({"error": "Email, OTP, and new password are required"}), 400

    # Check if the user is a doctor
    user = Doctor_collection.find_one({"email": email, "otp": otp})
    if user:
        # Reset password
        new_hashed_password = generate_password_hash(new_password)
        Doctor_collection.update_one(
            {"email": email},
            {"$set": {"password": new_hashed_password, "otp": None}}  # Clear OTP after use
        )
        return jsonify({"message": "Password reset successfully for doctor."}), 200

    # Check if the user is a student
    user = Student_collection.find_one({"email": email, "otp": otp})
    if user:
        # Reset password
        new_hashed_password = generate_password_hash(new_password)
        Student_collection.update_one(
            {"email": email},
            {"$set": {"password": new_hashed_password, "otp": None}}  # Clear OTP after use
        )
        return jsonify({"message": "Password reset successfully for student."}), 200

    return jsonify({"error": "Invalid email or OTP"}), 400




if __name__ == '__main__':
    app.run(debug=True)