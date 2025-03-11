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
import base64
import boto3
from botocore.exceptions import NoCredentialsError
import uuid
from dotenv import load_dotenv







app = Flask(__name__)
uri = "mongodb+srv://pandukrishna04:Raina%40143@cluster0.4fkpx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db=client.get_database('Health')
Doctor_collection=db['Doctor']
Student_collection = db['Student']
organs_collection = db['Organs']

CORS(app)


Doctor_collection.create_index("email", unique=True)
Doctor_collection.create_index("doctorId", unique=True)


Student_collection.create_index("email", unique=True)
Student_collection.create_index("studentId", unique=True)



def generate_admin_credentials():
    """Generate admin username and password."""

    adminName = "Admin"  # Example admin name
    adminId = "ADMIN01"  # Example admin ID
    email = "teja.g@makonissoft.com"  # Example admin email
    username = "admin@1"
    password = "admin123"  # Use the same password generation function
    hashed_password = generate_password_hash(password)

    # Store credentials in environment variables or a secure location
    os.environ['ADMIN_NAME'] = adminName
    os.environ['ADMIN_ID'] = adminId
    os.environ['ADMIN_EMAIL'] = email
    os.environ['ADMIN_USERNAME'] = username
    os.environ['ADMIN_PASSWORD'] = hashed_password

    # For demonstration purposes, print the credentials


    print(f"Admin credentials - Name: {adminName}, ID: {adminId}, Email: {email}, Username: {username}, Password: {password}")


load_dotenv()
# Initialize the S3 client
s3= boto3.client('s3', aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='eu-north-1'
)

bucket_name = 'images09876'
def upload_base64_to_s3(base64_data, file_name):
    try:
        # Decode the Base64 data
        file_data = base64.b64decode(base64_data)

        # Generate a unique file name
        unique_id = str(uuid.uuid4())
        s3_key = f"uploads/{unique_id}_{file_name}"

        # Debug: Print the S3 key
        print(f"Uploading file: {s3_key}")

        # Determine the MIME type based on the file extension
        if file_name.lower().endswith('.jpg') or file_name.lower().endswith('.jpeg'):
            content_type = 'image/jpeg'
        elif file_name.lower().endswith('.png'):
            content_type = 'image/png'
        elif file_name.lower().endswith('.gif'):
            content_type = 'image/gif'
        else:
            content_type = 'binary/octet-stream'  # Default MIME type

        # Upload to S3 with the correct MIME type and make it publicly accessible
        s3.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=file_data,
            ContentType=content_type,  # Set the MIME type
            ACL='public-read'  # Make the object publicly readable
        )

        # Debug: Confirm the upload
        print(f"File uploaded successfully: {s3_key}")

        # Generate the public URL
        public_url = f"https://{bucket_name}.s3.{s3.meta.region_name}.amazonaws.com/{s3_key}"

        # Return the public URL
        return public_url
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
        print(f"Bucket: {bucket_name}, Key: {s3_key}")
        return None

generate_admin_credentials()


def generate_password(length=12):
    """Generates a random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_username(usertype):
    """Generate a username in the format 'student@<number>' or 'doctor@<number>'."""
    if usertype == "student":
        count = Student_collection.count_documents({}) + 1
        return f"student@{count}"
    elif usertype == "doctor":
        count = Doctor_collection.count_documents({}) + 1
        return f"doctor@{count}"
    else:
        raise ValueError("Invalid usertype. Must be 'student' or 'doctor'.")



def send_email(recipient, username, password):

    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    message = f"""Subject: Your Login Details

    Dear Doctor,

    Your account has been created. Here are your login details:

    Username: {username}
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

        # Generate a username
        username = generate_username("doctor")

        # Create a new doctor document with timestamp
        doctor = {
            "doctorname": doctorname,
            "email": email,
            "mobile": mobile,
            "doctorId": doctorId,
            "designation": designation,
            "placeOfWork": placeOfWork,
            "usertype": "doctor",
            "username": username,  # Add username
            "password": hashed_password,
            "timestamp": datetime.now()  # Add current date and time
        }

        # Send email with login details
        send_email(email, username, password)  # Include username in the email

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

        # Generate a username
        username = generate_username("student")

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
            "username": username,  # Add username
            "password": hashed_password,
            "timestamp": datetime.now()  # Add current date and time
        }

        # Insert the student into the collection
        Student_collection.insert_one(student)

        # Send email with login details
        send_student_email(email, username, password)  # Include username in the email

        return jsonify({"message": "Student registered successfully! Login details sent to email."}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred during registration: {str(e)}"}), 500

def send_student_email(recipient, username, password):
    """Send an email with student login details."""
    sender_email = "vutukuridinesh18@gmail.com"
    sender_password = "krvz zgas bqsu ymuh"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    message = f"""Subject: Your Student Login Details

    Dear Student,

    Your account has been created. Here are your login details:

    Username: {username}
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

        username = data.get('username')  # Use username instead of email
        password = data.get('password')

        # Check if the user is an admin
        stored_username = os.environ.get('ADMIN_USERNAME')
        stored_password = os.environ.get('ADMIN_PASSWORD')
        stored_adminName=os.environ.get('ADMIN_NAME')
        stored_adminId=os.environ.get('ADMIN_ID')
        stored_email=os.environ.get('ADMIN_EMAIL')
        if username == stored_username and check_password_hash(stored_password, password):
            return jsonify({
                "message": "Login successful",
                "user": {
                    "username": stored_username,
                    "usertype": "admin",
                    "adminName": stored_adminName,
                    "adminId":stored_adminId,
                    "email":stored_email
                }
            }), 200

        # Check if the user is a doctor
        doctor = Doctor_collection.find_one({"username": username})
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
        student = Student_collection.find_one({"username": username})
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
        return jsonify({"error": "Invalid username or password"}), 401

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
        },
    "spinalcord": {
                "parts": [
                    "cervicalRegion", "thoracicRegion", "lumbarRegion", "sacralRegion",
                    "coccygealRegion", "grayMatter", "whiteMatter", "dorsalRoot",
                    "ventralRoot", "vertebralColumn", "meninges", "cerebrospinalFluid",
                    "classification"
                ]
            },
    "lung": {
            "parts": [
                "rightUpperLobe", "rightMiddleLobe", "rightLowerLobe", "leftUpperLobe",
                "leftLowerLobe", "mainBronchi", "lobarBronchi", "segmentalBronchi",
                "visceralPleura", "parietalPleura", "alveoli", "classification"
            ]
        },
    "kidney": {
            "parts": [
                "renalCapsule", "hilum", "renalCortex", "renalMedulla", "renalPelvis",
                "renalCorpuscle", "proximalConvolutedTubule", "loopOfHenle",
                "distalConvolutedTubule", "collectingDuct", "bloodSupply", "additionalClassification"
            ]
        },
    "skin": {
            "parts": [
        "keratinocytes", "melanocytes", "langerhansCells", "merkelCells",
        "adiposeTissue", "bloodVesselsHypodermis",
        "collagenElastinFibers", "bloodVesselsDermis", "nerveEndings",
        "hairFollicles", "sebaceousGlands",
        "protection", "regulation", "sensation", "metabolism",
        "excretion", "additionalClassification"

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

        # Check if the student has already submitted conditions for this organ
        existing_conditions = organs_collection.find_one(
            {"studentId": student_id, "organ": organ, "conditions": {"$exists": True}}
        )
        if existing_conditions:
            return jsonify({"error": f"Student has already submitted the form for {organ}"}), 400

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
                        "clinicalObservations": condition.get('clinicalObservations', ''),
                        "bloodTests": condition.get('bloodTests', ''),
                        "urineTests": condition.get('urineTests', ''),
                        "heartRate": condition.get('heartRate', ''),
                        "bloodPressure": condition.get('bloodPressure', ''),
                        "xRays": condition.get('xRays', ''),
                        "mriScans": condition.get('mriScans', '')
                    }

                    # Use part_key (e.g., addEpicardium) for storage
                    if part_key not in temporary_conditions[student_id]:
                        temporary_conditions[student_id][part_key] = []

                    temporary_conditions[student_id][part_key].append(condition_entry)

        print(f"Temporary conditions after adding for {student_id}: {temporary_conditions}")  # Debug log
        return jsonify({"message": f"Conditions added successfully for {organ}"}), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


def is_valid_base64(data):
    try:
        base64.b64decode(data, validate=True)
        return True
    except Exception:
        return False
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

        # Check if the student has already submitted a form for this organ
        existing_form = organs_collection.find_one({"studentId": student_id, "organ": organ})
        if existing_form:
            return jsonify({"error": f"Student has already submitted a form for {organ}"}), 400

        # Check database connection
        if Student_collection is None or organs_collection is None:
            return jsonify({"error": "Database connection failed"}), 500

        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

        timestamp = datetime.now()
        organ_data = {
            "organ": organ,
            "studentId": student_id,
            "status": "pending",
            "timestamp": timestamp
        }

        # Add organ-specific text fields and image fields
        organ_parts = organs_structure.get(organ, {}).get("parts", [])
        input_fields = {}

        for part in organ_parts:
            # Store text field (if provided)
            if part in data:
                input_fields[part] = data.get(part, "")

            # Store Base64-encoded image field (if provided and valid)
            image_field = f"{part}Image"
            if image_field in data and data[image_field]:  # Check if the field exists and is not empty
                if not is_valid_base64(data[image_field]):
                    return jsonify({"error": f"Invalid Base64 data in {image_field}"}), 400

                # Upload the image to S3 and get the public URL
                public_url = upload_base64_to_s3(data[image_field], f"{part}.jpg")
                if not public_url:
                    return jsonify({"error": f"Failed to upload {image_field} to S3"}), 500

                # Store the public URL for the specific image field
                input_fields[image_field] = public_url

        organ_data["inputfields"] = input_fields

        # Add conditions if they exist
        if student_id in temporary_conditions:
            organ_data["conditions"] = temporary_conditions[student_id]
            del temporary_conditions[student_id]
        else:
            organ_data["conditions"] = {}

        # Log the data to be inserted
        print("Organ Data to be inserted:", organ_data)

        # Insert the form into the Organs collection
        result = organs_collection.insert_one(organ_data)
        print("Insertion result:", result.inserted_id)

        if result.inserted_id:
            return jsonify({
                "message": f"Form submitted successfully for {organ}",
                "id": str(result.inserted_id),
                "timestamp": timestamp
            }), 201
        else:
            return jsonify({"error": "Failed to submit data"}), 500

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
@app.route('/count_unapproved_forms', methods=['GET'])
def count_forms_by_doctor():
    try:
        # Fetch all forms with status "pending" from the Organs collection
        forms = organs_collection.find({"status": "pending"})

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
        # Fetch all forms with status "pending", "approved", or "rejected"
        forms = organs_collection.find({"status": {"$in": ["pending", "approved", "rejected"]}})

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
                "doctorName":student["doctorname"],
                "formId": str(form["_id"]),  # Convert ObjectId to string
                "timestamp": form.get("timestamp"),  # Include submission timestamp
                "approved_timestamp": form.get("approved_timestamp"),  # Include approval timestamp
                "rejected_timestamp": form.get("rejected_timestamp"),  # Include rejection timestamp
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

        # Include approval/rejection timestamps in the response
        response_data = {
            **form,
            "approved_timestamp": form.get("approved_timestamp"),
            "rejected_timestamp": form.get("rejected_timestamp")
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/reject_form/<form_id>', methods=['POST'])
def reject_form(form_id):
    try:
        # Convert form_id to ObjectId
        form_object_id = ObjectId(form_id)

        # Check if the form exists
        existing_form = organs_collection.find_one({"_id": form_object_id})
        if not existing_form:
            return jsonify({"error": "Form not found"}), 404

        # Update the form status to "rejected" and add rejection timestamp
        result = organs_collection.update_one(
            {"_id": form_object_id},
            {"$set": {"status": "rejected", "rejected_timestamp": datetime.now()}}
        )

        # Log the updated form for debugging
        updated_form = organs_collection.find_one({"_id": form_object_id})
        print(f"Updated Form (Rejected): {updated_form}")

        if result.modified_count == 1:
            return jsonify({"message": "Form rejected successfully"}), 200
        else:
            return jsonify({"error": "Form not found or already rejected"}), 404

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/approve_form/<form_id>', methods=['POST'])
def approve_form(form_id):
    try:
        # Get request data
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
            "approved_timestamp": datetime.now()  # Add approval timestamp
        }

        # Update inputfields if provided
        if "inputfields" in data:
            updated_form_data["inputfields"] = data["inputfields"]

        # Update conditions if provided
        if "conditions" in data:
            updated_form_data["conditions"] = data["conditions"]

        # Update the form in the database
        result = organs_collection.update_one(
            {"_id": form_object_id},
            {"$set": updated_form_data}
        )

        # Log the updated form for debugging
        updated_form = organs_collection.find_one({"_id": form_object_id})
        print(f"Updated Form (Approved): {updated_form}")

        if result.modified_count == 1:
            return jsonify({"message": "Form approved and updated successfully"}), 200
        else:
            return jsonify({"error": "Form not found or no changes made"}), 404

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/get_all_doctors', methods=['GET'])
def get_all_doctors():
    try:
        # Fetch all doctors from the Doctor collection
        doctors = Doctor_collection.find({}, {"doctorname": 1, "email": 1, "doctorId": 1, "_id": 0, "designation": 1})

        # Prepare the response data
        doctors_list = []
        for doctor in doctors:
            doctors_list.append({
                "name": doctor["doctorname"],
                "email": doctor["email"],
                "doctorId": doctor["doctorId"], # Include doctorId
                "designation" : doctor['designation']
            })

        return jsonify(doctors_list), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500



@app.route('/get_all_students', methods=['GET'])
def get_all_students():
    try:
        # Fetch all students from the Student collection
        students = Student_collection.find({}, {"studentname": 1, "email": 1, "studentId": 1, "_id": 0})

        # Prepare the response data
        students_list = []
        for student in students:
            students_list.append({
                "name": student["studentname"],
                "email": student["email"],
                "studentId": student["studentId"]  # Include studentId
            })

        return jsonify(students_list), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500



@app.route('/get_counts', methods=['GET'])
def get_counts():
    try:


        # Count approved forms
        approved_forms = organs_collection.count_documents({"status": "approved"})

        # Count rejected forms
        rejected_forms = organs_collection.count_documents({"status": "rejected"})

        # Count pending forms
        pending_forms = organs_collection.count_documents({"status": "pending"})

        # Count available doctors
        available_doctors = Doctor_collection.count_documents({})

        # Count available students
        available_students = Student_collection.count_documents({})

        # Prepare the response data
        counts = {
            "approved_forms": approved_forms,
            "rejected_forms": rejected_forms,
            "pending_forms": pending_forms,
            "available_doctors": available_doctors,
            "available_students": available_students
        }

        return jsonify(counts), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/update_doctor/<doctorId>', methods=['PUT'])
def update_doctor(doctorId):
    try:
        # Get the updated doctor details from the request
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Prepare the update data
        update_data = {}
        if "doctorname" in data:
            update_data["doctorname"] = data["doctorname"]
        if "email" in data:
            update_data["email"] = data["email"]
        if "designation" in data:
            update_data["designation"] = data["designation"]

        # Check if there is any data to update
        if not update_data:
            return jsonify({"error": "No fields to update"}), 400

        # Update the doctor details in the database
        result = Doctor_collection.update_one(
            {"doctorId": doctorId},
            {"$set": update_data}
        )

        # Check if the doctor was found and updated
        if result.matched_count == 0:
            return jsonify({"error": "Doctor not found"}), 404

        return jsonify({"message": "Doctor details updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/delete_doctor/<doctorId>', methods=['DELETE'])
def delete_doctor(doctorId):
    try:
        # Delete the doctor from the database
        result = Doctor_collection.delete_one({"doctorId": doctorId})

        # Check if the doctor was found and deleted
        if result.deleted_count == 0:
            return jsonify({"error": "Doctor not found"}), 404

        return jsonify({"message": "Doctor deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/update_student/<studentId>', methods=['PUT'])
def update_student(studentId):
    try:
        # Get the updated student details from the request
        data = request.json
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        # Prepare the update data
        update_data = {}
        if "studentname" in data:
            update_data["studentname"] = data["studentname"]
        if "email" in data:
            update_data["email"] = data["email"]


        # Check if there is any data to update
        if not update_data:
            return jsonify({"error": "No fields to update"}), 400

        # Update the student details in the database
        result = Student_collection.update_one(
            {"studentId": studentId},
            {"$set": update_data}
        )

        # Check if the student was found and updated
        if result.matched_count == 0:
            return jsonify({"error": "Student not found"}), 404

        return jsonify({"message": "Student details updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500










if __name__ == '__main__':
    app.run(debug=True)