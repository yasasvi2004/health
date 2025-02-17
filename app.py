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
from datetime import datetime







app = Flask(__name__)
uri = "mongodb+srv://pandukrishna04:Raina%40143@cluster0.4fkpx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db=client.get_database('Health')
Doctor_collection=db['Doctor']
Student_collection = db['Student']
HeartAnatomy_collection = db['HeartAnatomy']
organs_collection = db['Organs']

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



def generate_doctor_id():
    """Generate a unique doctor ID."""
    prefix = "DOC"
    random_number = random.randint(10000, 99999)  # Adjust range as needed
    doctor_id = f"{prefix}{random_number}"
    return doctor_id





@app.route('/register', methods=['POST'])
def register_doctor():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Validate input data
        doctorname = data.get('doctorname')
        email = data.get('email')
        mobile = data.get('mobile')
        designation = data.get('designation')
        placeOfWork = data.get('placeOfWork')

        if not all([doctorname, email, mobile, designation, placeOfWork]):
            return jsonify({"error": "Missing required fields"}), 400

        if Doctor_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400

        # Generate a unique doctor ID
        doctorId = generate_doctor_id()
        while Doctor_collection.find_one({"doctorId": doctorId}):
            doctorId = generate_doctor_id()  # Regenerate if not unique

        # Generate a random password
        password = generate_password()

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new doctor document with timestamp
        doctor = {
            "doctorname": doctorname,
            "email": email,
            "mobile": mobile,
            "doctorId": doctorId,
            "designation": designation,
            "placeOfWork": placeOfWork,
            "usertype": "doctor",
            "password": hashed_password,
            "timestamp": datetime.now()  # Add current date and time
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
        studentname = data.get('studentname')
        email = data.get('email')
        phone = data.get('phone')
        college = data.get('college')
        degree = data.get('degree')
        doctorname = data.get('doctorname')
        doctorId = data.get('doctorId')

        required_fields = [studentname, email, phone, college, degree, doctorname, doctorId]
        if not all(required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Check for existing email
        if Student_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400

        # Check if the doctor exists
        doctor = Doctor_collection.find_one({"doctorId": doctorId, "doctorname": doctorname})
        if not doctor:
            return jsonify({"error": "Doctor does not exist with the provided ID and name."}), 400

        # Generate a unique student ID
        studentId = generate_student_id()
        while Student_collection.find_one({"studentId": studentId}):
            studentId = generate_student_id()  # Regenerate if not unique

        # Generate a random password and hash it
        password = generate_password()
        hashed_password = generate_password_hash(password)

        # Create a new student document with timestamp
        student = {
            "studentname": studentname,
            "email": email,
            "phone": phone,
            "studentId": studentId,
            "college": college,
            "degree": degree,
            "doctorname": doctorname,
            "doctorId": doctorId,
            "usertype": "student",
            "password": hashed_password,
            "timestamp": datetime.now()  # Add current date and time
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
                    "doctorName": doctor['doctorname'],
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
                    "studentname": student['studentname'],
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


organs_structure = {
    "heart": {
        "parts": [
            "epicardium", "myocardium", "endocardium", "rightAtrium", "rightVentricle",
            "leftAtrium", "leftVentricle", "tricuspidValve", "pulmonaryValve",
            "mitralValve", "aorticValve", "aorta", "pulmonaryArteries", "pulmonaryVeins",
            "venaCavae", "classification"
        ]
    },
    "brain": {
            "parts": [
                "frontalLobe", "parietalLobe", "temporalLobe", "occipitalLobe",
                "midbrain", "pons", "medullaOblongata", "cerebellum",
                "amygdala", "hippocampus", "thalamus", "corpusCallosum",
                "basalGanglia", "ventricles", "classification"
            ]
        }
    # Add more organs as needed
}

def validate_organ(organ):
    """Check if the organ exists in the organs_structure dictionary."""
    if organ.lower() not in organs_structure:
        return False
    return True

@app.route('/add_condition/<organ>', methods=['POST'])
def add_condition(organ):
    try:
        # Validate organ name
        if not validate_organ(organ):
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        student_id = data.get('studentId')
        if not student_id:
            return jsonify({"error": "Student ID is required"}), 400

        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

        if student_id not in temporary_conditions:
            temporary_conditions[student_id] = {}

        organ_parts = organs_structure.get(organ, {}).get("parts", [])
        for part in organ_parts:
            part_key = f"add{part[0].upper()}{part[1:]}"  # This creates addEpicardium, etc.
            if part_key in data:
                for condition in data[part_key]:
                    condition_entry = {
                        "clinicalCondition": condition.get('clinicalCondition', ''),
                        "symptoms": condition.get('symptoms', ''),
                        "signs": condition.get('signs', ''),
                        "clinicalObservations": condition.get('clinicalObservations', '')
                    }

                    # Use part_key (e.g., addEpicardium) for storage
                    if part_key not in temporary_conditions[student_id]:
                        temporary_conditions[student_id][part_key] = []

                    temporary_conditions[student_id][part_key].append(condition_entry)

        print(f"Temporary conditions after adding for {student_id}: {temporary_conditions}")  # Debug log
        return jsonify({"message": f"Conditions added successfully for {organ}"}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/submit_form/<organ>', methods=['POST'])
def submit_form(organ):
    try:
        # Validate organ name
        if not validate_organ(organ):
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        student_id = data.get('studentId')
        if not student_id:
            return jsonify({"error": "Student ID is required"}), 400

        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

        timestamp = datetime.now()
        organ_data = {
            "organ": organ,  # Store the organ name
            "studentId": student_id,
            "status": "pending",
            "timestamp": timestamp
        }


        # Add organ-specific data
        organ_parts = organs_structure.get(organ, {}).get("parts", [])
        organ_data["inputfields"] = {part: data.get(part, "") for part in organ_parts}

        # Add conditions if they exist
        if student_id in temporary_conditions:
            organ_data["conditions"] = temporary_conditions[student_id]
            del temporary_conditions[student_id]
        else:
            organ_data["conditions"] = {}

        # Insert the form into the Organs collection
        result = organs_collection.insert_one(organ_data)
        if result.inserted_id:
            return jsonify({
                "message": f"Form submitted successfully for {organ}",
                "id": str(result.inserted_id),
                "timestamp": timestamp
            }), 201
        else:
            return jsonify({"error": "Failed to submit data"}), 500

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
@app.route('/count_unapproved_forms', methods=['GET'])
def count_forms_by_doctor():
    try:
        # Get doctorId from query parameters
        doctor_id = request.args.get('doctorId')
        if not doctor_id:
            return jsonify({"error": "doctorId is required"}), 400

        # Find all students registered by this doctor
        students = Student_collection.find({"doctorId": doctor_id})
        student_ids = [student["studentId"] for student in students]

        # Fetch all pending forms for these students
        forms = organs_collection.find({
            "studentId": {"$in": student_ids},
            "status": "pending"
        })

        # Group forms by organ type
        organ_counts = {}
        for form in forms:
            organ = form.get("organ")
            if organ:
                if organ in organ_counts:
                    organ_counts[organ] += 1
                else:
                    organ_counts[organ] = 1

        # Return the organ counts as a JSON response
        return jsonify(organ_counts), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/get_unapproved_forms', methods=['GET'])
def get_forms_by_doctor():
    try:
        # Get doctorId from query parameters
        doctor_id = request.args.get('doctorId')
        if not doctor_id:
            return jsonify({"error": "doctorId is required"}), 400

        # Find all students registered by this doctor
        students = Student_collection.find({"doctorId": doctor_id})
        student_ids = [student["studentId"] for student in students]

        # Fetch all forms from the Organs collection for these students
        forms = organs_collection.find({
            "studentId": {"$in": student_ids},
            "status": "pending"
        })

        # Prepare the response data
        response_data = []
        for form in forms:
            # Fetch student details
            student = Student_collection.find_one({"studentId": form["studentId"]})
            if not student:
                continue  # Skip if student not found

            # Prepare the card data
            card_data = {
                "studentId": student["studentId"],
                "studentName": student["studentname"],
                "doctorId": student["doctorId"],
                "formId": str(form["_id"]),  # Convert ObjectId to string
                "timestamp": form.get("timestamp"),  # Include timestamp
                "status": form.get("status"),  # Include form status
                "organ": form.get("organ")  # Include organ type
            }
            response_data.append(card_data)

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/fetch_form_details/<form_id>', methods=['GET'])
def fetch_form_details(form_id):
    try:
        # Convert form_id to ObjectId
        form_object_id = ObjectId(form_id)

        # Fetch the form details from the Organs collection
        form = organs_collection.find_one({"_id": form_object_id})
        if not form:
            return jsonify({"error": "Form not found"}), 404

        # Convert ObjectId to string for JSON serialization
        form["_id"] = str(form["_id"])

        return jsonify(form), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/reject_form/<form_id>', methods=['POST'])
def reject_form(form_id):
    try:
        form_object_id = ObjectId(form_id)
        result = organs_collection.update_one(
            {"_id": form_object_id},
            {"$set": {"status": "rejected"}}
        )
        if result.modified_count == 1:
            return jsonify({"message": "Form rejected successfully"}), 200
        else:
            return jsonify({"error": "Form not found or already rejected"}), 404

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/approve_form/<form_id>', methods=['POST'])
def approve_form(form_id):
    try:
        data = request.json
        print(f"Request Data: {data}")
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Convert form_id to ObjectId
        form_object_id = ObjectId(form_id)

        # Fetch the existing form from the database
        existing_form = organs_collection.find_one({"_id": form_object_id})
        print(f"Existing Form: {existing_form}")
        if not existing_form:
            return jsonify({"error": "Form not found"}), 404

        # Prepare the updated form data
        updated_form_data = {
            "status": "approved",  # Update status to "approved"
            "timestamp": datetime.now()  # Update timestamp to the current time
        }

        # Update fields from inputFields if provided
        if "inputfields" in data:
            for field, value in data["inputfields"].items():
                updated_form_data[field] = value

        # Update conditions if provided
        if "conditions" in data:
            updated_form_data["conditions"] = data["conditions"]

        # Update the form in the database
        result = organs_collection.update_one(
            {"_id": form_object_id},
            {"$set": updated_form_data}
        )

        if result.modified_count == 1:
            return jsonify({"message": "Form approved and updated successfully"}), 200
        else:
            return jsonify({"error": "Form not found or no changes made"}), 404

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True)