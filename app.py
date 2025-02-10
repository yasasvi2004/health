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
from bson.objectid import ObjectId






app = Flask(__name__)
uri = "mongodb+srv://pandukrishna04:Raina%40143@cluster0.4fkpx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db=client.get_database('Health')
Doctor_collection=db['Doctor']
Student_collection = db['Student']
HeartAnatomy_collection = db['HeartAnatomy']

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



def generate_student_id():
    """Generate a unique student ID."""
    prefix = "STU"
    random_number = random.randint(10000, 99999)  # Adjust range as needed
    student_id = f"{prefix}{random_number}"
    return student_id

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
        college = data.get('college')
        degree = data.get('degree')

        if not all([name, email, phone, college, degree]):
            return jsonify({"error": "Missing required fields"}), 400

        # Check for existing email in the approved collection
        if Student_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400

        # Generate a unique student ID
        studentId = generate_student_id()
        while Student_collection.find_one({"studentId": studentId}):
            studentId = generate_student_id()  # Regenerate if not unique

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



# Temporary storage for conditions (in-memory, replace with a database in production)
temporary_conditions = {}


@app.route('/add_condition', methods=['POST'])
def add_condition():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        student_id = data.get('studentId')

        # Heart parts to check
        heart_parts = [
            "addEpicardium", "addMyocardium", "addEndocardium",
            "addRightAtrium", "addRightVentricle", "addLeftAtrium",
            "addLeftVentricle", "addTricuspidValve", "addPulmonaryValve",
            "addMitralValve", "addAorticValve", "addAorta",
            "addPulmonaryArteries", "addPulmonaryVeins", "addVenaCavae",
            "addClassification"
        ]

        # Check if the student exists
        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

            # Initialize temporary storage for the student if not exists
        if student_id not in temporary_conditions:
            temporary_conditions[student_id] = {}

            # Process each heart part in the payload
        for heart_part in heart_parts:
            if heart_part in data:  # Check if the heart part exists in the incoming data
                for condition in data[heart_part]:
                    # Create condition entry
                    condition_entry = {
                        "clinicalCondition": condition.get('clinicalCondition', ''),
                        "symptoms": condition.get('symptoms', ''),
                        "signs": condition.get('signs', ''),
                        "clinicalObservations": condition.get('clinicalObservations', '')
                    }

                    # If this heart part is not already in temporary storage, initialize it
                    if heart_part not in temporary_conditions[student_id]:
                        temporary_conditions[student_id][heart_part] = []

                        # Add the condition to temporary storage for the specific heart part
                    temporary_conditions[student_id][heart_part].append(condition_entry)

        return jsonify({"message": "Conditions added successfully"}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/submit_form', methods=['POST'])
def submit_form():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        student_id = data.get('studentId')
        # Validate student ID existence
        if not student_id:
            return jsonify({"error": "Student ID is required"}), 400

        # Check if student exists
        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

        # Prepare the heart anatomy data
        heart_anatomy_data = {
            "studentId": student_id,
            "epicardium": data.get("epicardium", ""),
            "myocardium": data.get("myocardium", ""),
            "endocardium": data.get("endocardium", ""),
            "rightAtrium": data.get("rightAtrium", ""),
            "rightVentricle": data.get("rightVentricle", ""),
            "leftAtrium": data.get("leftAtrium", ""),
            "leftVentricle": data.get("leftVentricle", ""),
            "tricuspidValve": data.get("tricuspidValve", ""),
            "pulmonaryValve": data.get("pulmonaryValve", ""),
            "mitralValve": data.get("mitralValve", ""),
            "aorticValve": data.get("aorticValve", ""),
            "aorta": data.get("aorta", ""),
            "pulmonaryArteries": data.get("pulmonaryArteries", ""),
            "pulmonaryVeins": data.get("pulmonaryVeins", ""),
            "venaCavae": data.get("venaCavae", ""),
            "classification": data.get("classification", ""),
            "approvedByDoctor": False  # Default value
        }

        # Add temporarily stored conditions for the student
        if student_id in temporary_conditions:
            heart_anatomy_data["conditions"] = temporary_conditions[student_id]
            # Clear the temporary conditions after submission to reset for the next entry
            del temporary_conditions[student_id]
        else:
            heart_anatomy_data["conditions"] = {}

        # Insert the heart anatomy data into the database
        result = HeartAnatomy_collection.insert_one(heart_anatomy_data)
        if result.inserted_id:
            return jsonify({"message": "Form submitted successfully", "id": str(result.inserted_id)}), 201
        else:
            return jsonify({"error": "Failed to submit data"}), 500

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/count_unapproved_forms', methods=['GET'])
def count_unapproved_forms():
    try:
        # Count the number of documents where approvedByDoctor is False
        unapproved_count = HeartAnatomy_collection.count_documents({"approvedByDoctor": False})

        # Create a dictionary with the organ name and count
        response_data = {"heart": unapproved_count}

        # Return the dictionary as a JSON response
        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)