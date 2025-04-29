from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
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
import uuid
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
uri = os.getenv('MONGODB_URI')
client = MongoClient(uri)
db = client.get_database(os.getenv('MONGODB_DBNAME'))
Doctor_collection = db['Doctor']
Student_collection = db['Student']
organs_collection = db['Organs']
dictionary_collection = db['Information']

CORS(app)

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

Doctor_collection.create_index("email", unique=True)
Doctor_collection.create_index("doctorId", unique=True)

Student_collection.create_index("email", unique=True)
Student_collection.create_index("studentId", unique=True)

# Admin Configuration
ADMIN_NAME = os.getenv('ADMIN_NAME')
ADMIN_ID = os.getenv('ADMIN_ID')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Verify all admin credentials are set
if not all([ADMIN_NAME, ADMIN_ID, ADMIN_EMAIL, ADMIN_USERNAME, ADMIN_PASSWORD]):
    raise ValueError("Missing one or more admin credentials in environment variables")

# Hash the password once at startup
ADMIN_HASHED_PASSWORD = generate_password_hash(ADMIN_PASSWORD)

# Optionally print (remove in production)
print(f"Admin credentials loaded - Name: {ADMIN_NAME}, ID: {ADMIN_ID}")

# Initialize the S3 client
s3 = boto3.client('s3', aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
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
    sender_email = EMAIL_USER
    sender_password = EMAIL_PASSWORD
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
        specialization = data.get('specialization')
        placeOfWork = data.get('placeOfWork')

        if not all([doctorname, email, mobile, specialization, placeOfWork]):
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
            "specialization": specialization,
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
        organs = data.get('organs', [])  # Optional field, default to empty list

        # Check if registration is by admin or doctor
        is_admin_registration = 'adminName' in data and 'adminId' in data
        is_doctor_registration = 'doctorname' in data and 'doctorId' in data

        if not (is_admin_registration or is_doctor_registration):
            return jsonify({"error": "Missing registration authority (admin or doctor) details"}), 400

        required_fields = [studentname, email, phone, college, degree]
        if not all(required_fields):
            return jsonify({"error": "Missing required student fields"}), 400

        # Check for existing email
        if Student_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered."}), 400

        # If registration by doctor, verify doctor exists
        if is_doctor_registration:
            doctor = Doctor_collection.find_one({
                "doctorId": data['doctorId'],
                "doctorname": data['doctorname']
            })
            if not doctor:
                return jsonify({"error": "Doctor does not exist with the provided ID and name."}), 400
            registration_authority = {
                "doctorname": data['doctorname'],
                "doctorId": data['doctorId']
            }
        else:  # Admin registration
            # Verify admin credentials (optional additional security check)
            if data['adminId'] != os.getenv('ADMIN_ID') or data['adminName'] != os.getenv('ADMIN_NAME'):
                return jsonify({"error": "Invalid admin credentials"}), 403
            registration_authority = {
                "doctorname": data['adminName'],  # Stored as doctorname for consistency
                "doctorId": data['adminId']  # Stored as doctorId for consistency
            }

        # Generate a unique student ID
        studentId = generate_student_id()
        while Student_collection.find_one({"studentId": studentId}):
            studentId = generate_student_id()

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
            "doctorname": registration_authority["doctorname"],
            "doctorId": registration_authority["doctorId"],
            "usertype": "student",
            "username": username,
            "password": hashed_password,
            "timestamp": datetime.now(),
            "organs": organs  # Store the list of organs
        }

        # Insert the student into the collection
        Student_collection.insert_one(student)

        # Send email with login details
        send_student_email(email, username, password)

        return jsonify({
            "message": "Student registered successfully! Login details sent to email.",
            "studentId": studentId
        }), 201

    except Exception as e:
        return jsonify({"error": f"An error occurred during registration: {str(e)}"}), 500


def send_student_email(recipient, username, password):
    """Send an email with student login details."""
    sender_email = EMAIL_USER
    sender_password = EMAIL_PASSWORD
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
        if username == ADMIN_USERNAME:
            if check_password_hash(ADMIN_HASHED_PASSWORD, password):
                return jsonify({
                    "message": "Login successful",
                    "user": {
                        "username": ADMIN_USERNAME,
                        "usertype": "admin",
                        "adminName": ADMIN_NAME,
                        "adminId": ADMIN_ID,
                        "email": ADMIN_EMAIL
                    }
                }), 200
            else:
                return jsonify({"error": "Invalid admin password"}), 401

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
                    "specialization": doctor['specialization'],
                    "placeOfWork": doctor['placeOfWork'],
                    "usertype": "doctor"
                }
            }), 200

        # Check if the user is a student
        student = Student_collection.find_one({"username": username})
        if student and check_password_hash(student['password'], password):
            student_organs = student.get('organs', [])
            return jsonify({
                "message": "Login successful",
                "user": {
                    "studentname": student['studentname'],
                    "email": student['email'],
                    "phone": student['phone'],
                    "studentId": student['studentId'],
                    "college": student['college'],
                    "degree": student['degree'],
                    "usertype": "student",
                    "organs": student_organs
                }
            }), 200

        # If no match is found
        return jsonify({"error": "Invalid username or password"}), 401

    except Exception as e:
        return jsonify({"error": f"An error occurred during login: {str(e)}"}), 500


def send_reset_email(recipient, usertype):
    """Send an email notifying the user of a successful password reset."""
    sender_email = EMAIL_USER
    sender_password = EMAIL_PASSWORD
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
        sender_email = EMAIL_USER
        sender_password = EMAIL_PASSWORD
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
    },
    "ear": {
        "parts": [
            "pinna", "externalAuditoryCanal", "eardrum", "ossicles", "eustachianTube", "cochlea", "vestibularSystem",
            "additionalClassification"
        ]
    },
    "eye": {
        "parts": [
            "cornea", "iris", "pupil", "lens", "retina", "opticNerve", "vitreousHumor", "sclera", "choroid",
            "additionalClassification"
        ]
    },
    "gastrointestinal": {
        "parts": [
            "oralCavity", "esophagus", "stomach", "duodenum",
            "Jejunum", "Ileum", "cecum", "colon", "rectum",
            "liver", "gallbladder", "additionalClassification"
        ]
    },
    "reproductiveorganfemale": {
        "parts": [
            "ovaries", "fallopianTubes", "uterus", "vagina",
            "labiaMajora", "labiaMinora", "clitoris", "vaginalOpening",
            "hormonalRegulation", "additionalClassification"
        ]
    },
    "reproductiveorganmale": {
        "parts": [
            "testes", "epididymis", "vasDeferens", "seminalVesicles",
            "prostateGland", "bulbourethralGlands", "urethra",
            "penis", "additionalClassification"
        ]
    },
    "hematopoietic": {
        "parts": [
            "hematopoieticStemCells", "progenitorCells", "boneMarrow", "peripheralBlood",
            "spleen", "lymphNode", "myeloidLineage", "lymphoidLineage",
            "anemia", "leukemia", "thrombocytopenia", "additionalClassification"
        ]
    },
    "thyroid": {
        "parts": [
            "rightLobe", "leftLobe", "isthmus", "arterialSupply",
            "venousDrainage", "capsule", "innervation", "histology",
            "parathyroidGlands", "trachea", "additionalClassifications"
        ]
    },
    "pancreas": {
        "parts": [
            "exocrineTissue", "endocrineTissue",
            "digestiveFunction", "endocrineFunction",
            "additionalClassification"
        ]
    },
    "adrenalglands": {
        "parts": [
            "zonaGlomerulosa", "zonaFasciculata", "zonaReticularis",
            "superiorSuprarenalArteries", "middleSuprarenalArtery", "inferiorSuprarenalArteries",
            "adrenalMedulla", "additionalClassification"
        ]
    }
    # Add more organs as needed
}


def validate_organ(organ):
    """Check if the organ exists in the organs_structure dictionary."""
    if organ.lower() not in organs_structure:
        return False
    return True


@app.route('/get_clinical_conditions/<organ>/<part>', methods=['GET'])
def get_clinical_conditions_by_organ_and_part(organ, part):
    try:
        # Validate organ name
        if not validate_organ(organ):
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

        # Get all valid parts for this organ (case-insensitive check)
        organ_parts = organs_structure.get(organ, {}).get("parts", [])
        part_lower = part.lower()
        matched_part = next((p for p in organ_parts if p.lower() == part_lower), None)

        if not matched_part:
            return jsonify({"error": f"Invalid part '{part}' for organ '{organ}'"}), 400

        # Fetch forms that have conditions for this specific organ and part
        forms = organs_collection.find({
            "organ": organ,
            f"conditions.{matched_part}": {"$exists": True, "$ne": []}
        })

        clinical_conditions = []
        for form in forms:
            # Get conditions for the specific part
            part_conditions = form["conditions"].get(matched_part, [])

            if not part_conditions:
                continue

            # Fetch student details
            student = Student_collection.find_one({"studentId": form["studentId"]})
            if not student:
                continue

            # Clean conditions (remove null/empty fields)
            cleaned_conditions = []
            for condition in part_conditions:
                if condition:
                    cleaned_condition = {k: v for k, v in condition.items() if v is not None}
                    if cleaned_condition:
                        cleaned_condition["subpart"] = matched_part
                        cleaned_conditions.append(cleaned_condition)

            if cleaned_conditions:
                clinical_conditions.append({
                    "studentId": student["studentId"],
                    "studentName": student["studentname"],
                    "part": matched_part,
                    "organ": organ,
                    "noOfConditions": len(cleaned_conditions),
                    "conditions": {
                        f"record{i + 1}": cond for i, cond in enumerate(cleaned_conditions)
                    },
                    "submissionDate": form.get("timestamp"),
                    "status": form.get("status", "pending")
                })

        return jsonify({
            "organ": organ,
            "part": matched_part,
            "totalConditions": sum(len(item["conditions"]) for item in clinical_conditions),
            "clinicalConditions": clinical_conditions
        }), 200

    except Exception as e:
        return jsonify({
            "error": f"An error occurred: {str(e)}",
            "organ": organ,
            "part": part
        }), 500


def is_valid_base64(data):
    try:
        base64.b64decode(data, validate=True)
        return True
    except Exception:
        return False





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










@app.route('/get_unapproved_forms/<organ>', methods=['GET'])
def get_all_organ_forms(organ=None):
    try:
        # Build the query - filter by organ if provided
        query = {}
        if organ:
            # Validate the organ exists
            if organ.lower() not in organs_structure:
                return jsonify({"error": f"Invalid organ: {organ}"}), 400
            query["organ"] = organ.lower()

        # Optionally filter by status (e.g., pending)
        status = request.args.get('status')
        if status:
            query["status"] = status.lower()

        # Fetch organ forms based on query
        forms = list(organs_collection.find(query))

        # Prepare the response data
        forms_list = []
        for form in forms:
            # Get student details
            student = Student_collection.find_one({"studentId": form["studentId"]})
            if not student:
                continue

            forms_list.append({
                "_id": str(form["_id"]),  # Convert ObjectId to string
                "organ": form["organ"],
                "studentId": form["studentId"],
                "studentName": student["studentname"],
                "status": form.get("status", "pending"),
                "submissionDate": form.get("timestamp"),
                "lastUpdated": form.get("last_updated"),
                "doctorId": student.get("doctorId"),
                "doctorName": student.get("doctorname"),
                "partsSubmitted": list(form.get("inputfields", {}).keys())
            })

        return jsonify({
            "count": len(forms_list),
            "organ": organ if organ else "all",
            "forms": forms_list
        }), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/get_all_pending_forms', methods=['GET'])
def get_all_pending_forms():
    try:
        # Find all forms with status "pending"
        forms = list(organs_collection.find({
            "status": {"$in": ["pending", "approved", "rejected"]}
        }))

        # Gather all student IDs from the forms
        student_ids = {form["studentId"] for form in forms}

        # Retrieve students based on the collected student IDs
        students = {s["studentId"]: s for s in Student_collection.find({"studentId": {"$in": list(student_ids)}})}

        response_data = []

        for form in forms:
            student = students.get(form["studentId"])
            if not student:
                continue

            # Create card data for the response
            card_data = {
                "studentId": student["studentId"],
                "studentName": student["studentname"],
                "doctorId": student["doctorId"],
                "doctorName": student["doctorname"],
                "formId": str(form["_id"]),
                "timestamp": form.get("timestamp"),
                "status": form.get("status"),
                "organ": form.get("organ"),
                "approved_timestamp": form.get("approved_timestamp", None),
                "rejected_timestamp": form.get("rejected_timestamp", None)
            }
            response_data.append(card_data)

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route('/fetch_form_details/<organ>/<student_id>/<part>', methods=['GET'])
def fetch_form_details(organ, student_id, part):
    try:
        # Validate organ
        if not validate_organ(organ):
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

        # Find the student's organ submission
        form = organs_collection.find_one({
            "organ": organ,
            "studentId": student_id
        })

        if not form:
            return jsonify({"error": "Form not found"}), 404

        # Check if the requested part exists
        inputfields = form.get("inputfields", {})
        if part not in inputfields:
            return jsonify({"error": f"Part '{part}' not found in submission"}), 404

        # Prepare the response
        response = {
            "studentId": student_id,
            "organ": organ,
            "part": part,
            "partDetails": inputfields[part],
            "formStatus": form.get("status", "pending"),
            "submissionDate": form.get("timestamp"),
            "allPartsStatus": {
                p: data.get("status", "pending")
                for p, data in inputfields.items()
            }
        }

        # Add student details if needed
        student = Student_collection.find_one({"studentId": student_id})
        if student:
            response["studentName"] = student.get("studentname")
            response["college"] = student.get("college")

        return jsonify(response), 200

    except Exception as e:
        return jsonify({
            "error": str(e),
            "organ": organ,
            "studentId": student_id,
            "part": part
        }), 500


@app.route('/review_condition/<student_id>/<organ>/<part_name>/<int:condition_index>', methods=['POST'])
def review_condition(student_id, organ, part_name, condition_index):
    try:
        data = request.json
        action = data.get('action')  # 'approve', 'reject', or 'review'
        feedback = data.get('feedback')  # Optional
        reviewed_by = data.get('reviewed_by')  # Optional doctorId

        # Validate action
        if action not in ['approve', 'reject', 'review']:
            return jsonify({"error": "Invalid action. Must be 'approve', 'reject', or 'review'."}), 400

        # Find and validate the organ document
        organ_document = organs_collection.find_one({"studentId": student_id, "organ": organ})
        if not organ_document:
            return jsonify({"error": "Organ not found for student"}), 404

        # Validate the part exists
        if part_name not in organ_document.get('inputfields', {}):
            return jsonify({"error": f"Part {part_name} not found in inputfields"}), 404

        # Get and validate conditions
        part_conditions = organ_document['inputfields'][part_name].get('conditions', [])
        if condition_index >= len(part_conditions):
            return jsonify({"error": "Condition index out of range"}), 400

        new_status = 'approved' if action == 'approve' else 'rejected' if action == 'reject' else 'reviewed' if action =='review' else None

        # Prepare the update
        update_data = {
            f"inputfields.{part_name}.conditions.{condition_index}.status": new_status,
            f"inputfields.{part_name}.conditions.{condition_index}.reviewed_at": datetime.utcnow(),
            "last_updated": datetime.utcnow()
        }

        # Add optional fields if provided
        if reviewed_by is not None:
            update_data[f"inputfields.{part_name}.conditions.{condition_index}.reviewed_by"] = reviewed_by
        if feedback is not None:
            update_data[f"inputfields.{part_name}.conditions.{condition_index}.feedback"] = feedback

        # Perform the update
        result = organs_collection.update_one(
            {"studentId": student_id, "organ": organ},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            return jsonify({"error": "Student organ record not found."}), 404
        if result.modified_count == 0:
            return jsonify({"error": "No changes made, possibly wrong part_name or condition_index."}), 400

        # Check if all conditions in the part are resolved (approved/rejected)
        form = organs_collection.find_one({"studentId": student_id, "organ": organ})
        part_conditions = form['inputfields'][part_name].get('conditions', [])

        if all(cond.get('status') in ['approved', 'rejected'] for cond in part_conditions):
            # Update part status to "reviewed" if all conditions are resolved
            organs_collection.update_one(
                {"studentId": student_id, "organ": organ},
                {"$set": {f"inputfields.{part_name}.status": "reviewed"}}
            )

        return jsonify({
            "message": f"Condition {condition_index} for part '{part_name}' marked as {action} successfully.",
            "part_status": "reviewed" if all(
                cond.get('status') in ['approved', 'rejected'] for cond in part_conditions) else "pending"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/review_part/<student_id>/<organ>/<part_name>', methods=['POST'])
def review_part(student_id, organ, part_name):
    try:
        data = request.json
        action = data.get('action')  # 'approve' or 'reject'
        feedback = data.get('feedback')  # Optional
        reviewed_by = data.get('reviewed_by')

        if action not in ['approve', 'reject','review']:
            return jsonify({"error": "Invalid action. Must be 'approve' or 'reject'."}), 400



        # Find and validate the organ document
        organ_document = organs_collection.find_one({"studentId": student_id, "organ": organ})
        if not organ_document:
            return jsonify({"error": "Organ not found for student"}), 404

        # Validate the part exists
        if part_name not in organ_document.get('inputfields', {}):
            return jsonify({"error": f"Part {part_name} not found in inputfields"}), 404

        # Check if all conditions are already approved/rejected
        part_conditions = organ_document['inputfields'][part_name].get('conditions', [])
        if not all(cond.get('status') in ['approved', 'rejected'] for cond in part_conditions):
            return jsonify({
                "error": "Cannot approve/reject part until all conditions are approved or rejected",
                "unresolved_conditions": [
                    i for i, cond in enumerate(part_conditions)
                    if cond.get('status') not in ['approved', 'rejected']
                ]
            }), 400
        new_status = 'approved' if action == 'approve' else 'rejected' if action == 'reject' else 'review' if action == 'reviewed' else None
        # Prepare the update
        update_data = {
            f"inputfields.{part_name}.status": new_status,
            f"inputfields.{part_name}.reviewed_at": datetime.utcnow(),
            f"inputfields.{part_name}.reviewed_by": reviewed_by,
            "last_updated": datetime.utcnow()
        }

        if feedback is not None:
            update_data[f"inputfields.{part_name}.feedback"] = feedback

        # Perform the update
        result = organs_collection.update_one(
            {"studentId": student_id, "organ": organ},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            return jsonify({"error": "Student organ record not found."}), 404
        if result.modified_count == 0:
            return jsonify({"error": "No changes made, possibly wrong part_name."}), 400

        # Check if all parts are reviewed (approved/rejected)
        form = organs_collection.find_one({"studentId": student_id, "organ": organ})
        part_statuses = [part.get('status') for part in form['inputfields'].values()]

        if all(status in ['approved', 'rejected'] for status in part_statuses):
            # Update form status to "reviewed" if all parts are approved/rejected
            organs_collection.update_one(
                {"studentId": student_id, "organ": organ},
                {"$set": {"status": "reviewed"}}
            )
            form_status = "reviewed"
        else:
            form_status = "pending"

        return jsonify({
            "message": f"Part '{part_name}' marked as {action} successfully.",
            "form_status": form_status,
            "part_status": action
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route('/get_all_doctors', methods=['GET'])
def get_all_doctors():
    try:
        # Fetch all doctors from the Doctor collection
        doctors = Doctor_collection.find({},
                                         {"doctorname": 1, "email": 1, "doctorId": 1, "_id": 0, "specialization": 1})

        # Prepare the response data
        doctors_list = []
        for doctor in doctors:
            doctors_list.append({
                "name": doctor["doctorname"],
                "email": doctor["email"],
                "doctorId": doctor["doctorId"],  # Include doctorId
                "specialization": doctor['specialization']
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
        if "specialization" in data:
            update_data["specialization"] = data["specialization"]

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


@app.route('/submit_form/<organ>/<part>', methods=['POST'])
def submit_form(organ, part):
    try:
        # Validate organ exists
        if organ not in organs_structure:
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

        organ_parts = organs_structure[organ]["parts"]
        matched_part = next((p for p in organ_parts if p.lower() == part.lower()), None)

        if matched_part is None:
            return jsonify({"error": f"Invalid part: {part}"}), 400

        data = request.json
        if data is None:
            return jsonify({"error": "No input data provided"}), 400

        student_id = data.get('studentId')
        if student_id is None:
            return jsonify({"error": "Student ID is required"}), 400

        # Verify DB connections
        if Student_collection is None or organs_collection is None:
            return jsonify({"error": "Database connection failed"}), 500

        # Get student info
        student = Student_collection.find_one({"studentId": student_id})
        if student is None:
            return jsonify({"error": "Student not found"}), 404

        timestamp = datetime.now()

        # Check if organ document exists for this student
        existing_organ = organs_collection.find_one({
            "studentId": student_id,
            "organ": organ
        })

        # Check if part was already submitted (but only check for complete submissions)
        if existing_organ and existing_organ.get('inputfields', {}).get(matched_part, {}).get('text'):
            return jsonify({"error": f"Already submitted {matched_part} for {organ}"}), 400

        # Prepare the base part data
        part_data = {
            "text": data.get(matched_part, ''),
            "image_url": None,
            "submitted_at": timestamp,
            "status": "pending"
        }

        # Handle image upload
        image_field = f"{matched_part}Image"
        if data.get(image_field):
            if not is_valid_base64(data[image_field]):
                return jsonify({"error": "Invalid image data"}), 400

            public_url = upload_base64_to_s3(
                data[image_field],
                f"{organ}_{matched_part}_{student_id}.jpg"
            )
            part_data["image_url"] = public_url

        # If document exists, update it while preserving any existing conditions
        if existing_organ:
            # Get existing conditions if they exist
            existing_conditions = existing_organ.get('inputfields', {}).get(matched_part, {}).get('conditions', [])
            if existing_conditions:
                part_data['conditions'] = existing_conditions

            update_data = {
                f"inputfields.{matched_part}": part_data,
                "status": "pending",
                "last_updated": timestamp
            }

            # Update student name if not set
            if not existing_organ.get('studentName'):
                update_data['studentName'] = student.get('studentname')

            result = organs_collection.update_one(
                {"_id": existing_organ["_id"]},
                {"$set": update_data}
            )
            document_id = existing_organ["_id"]
        else:
            # Create new document
            organ_data = {
                "organ": organ,
                "studentId": student_id,
                "studentName": student.get('studentname'),
                "status": "pending",
                "timestamp": timestamp,
                "inputfields": {
                    matched_part: part_data
                },
                "last_updated": timestamp
            }
            result = organs_collection.insert_one(organ_data)
            document_id = result.inserted_id

        return jsonify({
            "message": f"{matched_part} submitted successfully",
            "document": {
                "id": str(document_id),
                "organ": organ,
                "part": matched_part,
                "isNewDocument": existing_organ is None
            }
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route('/submit_conditions/<student_id>/<organ>/<part>', methods=['POST'])
def submit_conditions(student_id, organ, part):
    try:
        # Normalize part name
        normalized_part = part.lower()

        # Validate organ exists
        if organ not in organs_structure:
            return jsonify({"error": f"Invalid organ: {organ}"}), 400

            # Find correct case for part name
        organ_parts = organs_structure[organ]["parts"]
        matched_part = next((p for p in organ_parts if p.lower() == normalized_part), None)
        if not matched_part:
            return jsonify({"error": f"Invalid part: {part}"}), 400

            # Validate student exists
        student = Student_collection.find_one({"studentId": student_id})
        if not student:
            return jsonify({"error": "Student not found"}), 404

            # Validate request data
        data = request.json
        if not data or not isinstance(data.get('conditions', []), list):
            return jsonify({"error": "Conditions data must be an array"}), 400

        timestamp = datetime.utcnow()
        conditions_data = []

        for condition in data['conditions']:
            if not condition.get('clinicalCondition'):
                return jsonify({"error": "clinicalCondition is required"}), 400

            conditions_data.append({
                "clinicalCondition": condition['clinicalCondition'],
                "symptoms": condition.get('symptoms', ''),
                "signs": condition.get('signs', ''),
                "clinicalObservations": condition.get('clinicalObservations', ''),
                "bloodTests": condition.get('bloodTests', ''),
                "urineTests": condition.get('urineTests', ''),
                "heartRate": condition.get('heartRate', ''),
                "bloodPressure": condition.get('bloodPressure', ''),
                "xRays": condition.get('xRays', ''),
                "mriScans": condition.get('mriScans', ''),
                "added_at": timestamp,
                "added_by": condition.get('doctorId'),
                "status": "pending"
            })

            # Find existing document or prepare new one
        existing_organ = organs_collection.find_one({"studentId": student_id, "organ": organ})

        if existing_organ:
            # Check if part exists but isn't an object
            if matched_part in existing_organ.get('inputfields', {}) and not isinstance(
                    existing_organ['inputfields'][matched_part], dict):
                return jsonify({
                    "error": f"Invalid existing data structure for part '{matched_part}'",
                    "solution": "Please contact admin to fix data consistency"
                }), 400

                # Prepare update operation
            update = {
                "$set": {
                    "last_updated": timestamp,
                    "studentName": student.get('studentname')
                },
                "$push": {f"inputfields.{matched_part}.conditions": {"$each": conditions_data}}
            }

            # If part doesn't exist, initialize it
            if matched_part not in existing_organ['inputfields']:
                update["$set"][f"inputfields.{matched_part}"] = {
                    "status": "pending",
                    "conditions": conditions_data
                }

            result = organs_collection.update_one(
                {"_id": existing_organ["_id"]},
                update
            )
        else:
            # Create new document
            organ_data = {
                "organ": organ,
                "studentId": student_id,
                "studentName": student.get('studentname'),
                "status": "pending",
                "inputfields": {
                    matched_part: {
                        "status": "pending",
                        "conditions": conditions_data
                    }
                },
                "last_updated": timestamp
            }
            result = organs_collection.insert_one(organ_data)

        return jsonify({
            "message": f"Conditions submitted successfully for {matched_part}",
            "count": len(conditions_data)
        }), 200

    except Exception as e:
        return jsonify({
            "error": str(e),
            "debug": "Please check if the document structure is consistent"
        }), 500



@app.route('/fetch_conditions/<student_id>/<organ>/<part>', methods=['GET'])
def fetch_conditions(student_id, organ, part):
    try:
        # Find the organ document for the student
        organ_document = organs_collection.find_one({
            "studentId": student_id,
            "organ": organ
        })

        if not organ_document:
            return jsonify({"error": "Organ not found for student"}), 404

        # Check if the part exists in inputfields
        if part not in organ_document['inputfields']:
            return jsonify({"error": f"Part {part} not found in inputfields"}), 404

        # Get the conditions for the part
        part_conditions = organ_document['inputfields'][part].get('conditions', [])

        return jsonify({
            "message": "Conditions fetched successfully.",
            "conditions": part_conditions
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/add_to_dictionary', methods=['POST'])
def add_to_dictionary():
    try:
        # Validate incoming data
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Check required 'term' field
        if 'term' not in data or not isinstance(data['term'], str):
            return jsonify({"error": "Missing or invalid field: term"}), 400

        term = data['term'].strip()
        if not term:
            return jsonify({"error": "Term cannot be empty"}), 400

        # Prepare dictionary entry
        dictionary_entry = {
            "term": term,
            "definition": data.get('definition', '').strip()  # Optional field
        }

        # Check for existing term (case-insensitive)
        existing_term = dictionary_collection.find_one({
            "term": {"$regex": f"^{term}$", "$options": "i"}
        })

        if existing_term:
            return jsonify({
                "error": "Term already exists",
                "existing_id": str(existing_term['_id']),
                "existing_term": existing_term['term']
            }), 409

        # Insert into database
        result = dictionary_collection.insert_one(dictionary_entry)

        # Return success response
        return jsonify({
            "message": "Term added to dictionary successfully",
            "id": str(result.inserted_id),
            "term": term,
            "definition": dictionary_entry['definition'] if dictionary_entry['definition'] else None,
        }), 201

    except Exception as e:
        app.logger.error(f"Error adding term: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500





if __name__ == '__main__':
    app.run(debug=True)