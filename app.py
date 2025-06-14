from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from functools import wraps
from models import db, User  # Import from models.py
import os
import numpy as np
from tensorflow.keras.models import load_model
from PIL import Image, ExifTags
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Ensure SQLALCHEMY_DATABASE_URI or SQLALCHEMY_BINDS is set
db_uri = os.getenv('DB_URI')
db_binds = os.getenv('DB_BINDS')  # Optional: for multiple databases

if not db_uri and not db_binds:
    raise RuntimeError("❌ Either 'SQLALCHEMY_DATABASE_URI' or 'SQLALCHEMY_BINDS' must be set. Please check your .env file.")

if db_uri:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
if db_binds:
    try:
        app.config['SQLALCHEMY_BINDS'] = eval(db_binds)  # Ensure DB_BINDS is a valid Python dictionary
    except Exception as e:
        raise RuntimeError(f"❌ Invalid DB_BINDS format: {str(e)}")

# Initialize SQLAlchemy with the app
db.init_app(app)

with app.app_context():
    db.create_all()

# Model configuration
MODEL_PATH = os.path.join('models', r'C:\Users\shiva\OneDrive\Desktop\madhav22\railway_restnet_finetuned.h5')
if not os.path.exists(MODEL_PATH):
    raise RuntimeError(f"❌ Model file not found at {MODEL_PATH}. Please check your model path.")       
try:
    model = load_model(MODEL_PATH)
except Exception as e:
    print(f"❌ Error loading model: {str(e)}")
    model = None

# File upload configuration
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Email alert function
def send_alert(email, image_path, location):
    sender_email = os.getenv('EMAIL_ADDRESS')
    sender_password = os.getenv('EMAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        print("❌ Email alerts disabled: Missing email credentials")
        return False
    
    if not email:
        print("❌ No recipient email provided")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = email
        msg["Subject"] = "🚨 Railway Track Defect Alert!"
        
        body = f"A defective track has been detected at location: {location}."
        msg.attach(MIMEText(body, "plain"))
        
        with open(image_path, "rb") as img:
            img_attachment = MIMEImage(img.read())
            img_attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(image_path))
            msg.attach(img_attachment)
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
            print("✅ Email alert sent successfully!")
            return True
    except Exception as e:
        print(f"❌ Email error: {str(e)}")
        return False

# SMS alert function
def send_sms_alert(phone_number, message):
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
    twilio_phone = os.getenv('TWILIO_PHONE')

    if not account_sid or not auth_token or not twilio_phone:
        print("❌ Missing Twilio credentials in environment variables.")
        return False

    try:
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=message,
            from_=twilio_phone,
            to=phone_number
        )
        print("✅ SMS alert sent successfully!")
        return True
    except Exception as e:
        print("❌ Error sending SMS alert:", str(e))
        return False

# ... [Keep all other functions and routes from original app.py] ...


# Function to convert DMS to Decimal Degrees
def convert_to_degrees(value):
    """Convert GPS coordinates from (degrees, minutes, seconds) fractions to decimal format."""
    return value[0] + (value[1] / 60.0) + (value[2] / 3600.0)

# Extract GPS metadata from an image
def get_gps_data(image_path):
    """Extracts GPS coordinates and converts them to decimal degrees."""
    try:
        img = Image.open(image_path)
        exif_data = img._getexif()
        if not exif_data:
            print("❌ No EXIF metadata found.")
            return "GPS data not available"

        gps_info = {}
        for tag, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag, tag)
            if tag_name == "GPSInfo":
                for gps_tag in value:
                    sub_tag_name = ExifTags.GPSTAGS.get(gps_tag, gps_tag)
                    gps_info[sub_tag_name] = value[gps_tag]

        if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
            lat = gps_info["GPSLatitude"]
            lon = gps_info["GPSLongitude"]

            lat_ref = gps_info.get("GPSLatitudeRef", "N")
            lon_ref = gps_info.get("GPSLongitudeRef", "E")

            # Convert GPS data to decimal format
            lat_decimal = convert_to_degrees(lat)
            lon_decimal = convert_to_degrees(lon)

            # Adjust sign based on hemisphere
            if lat_ref == "S":
                lat_decimal = -lat_decimal
            if lon_ref == "W":
                lon_decimal = -lon_decimal

            gps_coordinates = f"{lat_decimal:.6f}, {lon_decimal:.6f}"
            print(f"✅ Extracted GPS Data: {gps_coordinates}")
            return gps_coordinates
        else:
            print("❌ GPS data not found in metadata.")
            return "GPS data not available"
    except Exception as e:
        print("❌ Error extracting GPS data:", str(e))
        return "GPS data not available"

# Define login_required before using it in routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_user_by_username(username)
        if not user:
            flash('User not found. Please check your username or sign up.', 'error')
            return redirect(url_for('login'))
        
        if not user.check_password(password):
            flash('Incorrect password. Please try again.', 'error')  # Flash notification for incorrect password
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['username'] = user.username  # Store username in session
        flash('Login successful!', 'success')
        return redirect(url_for('home'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.get_user_by_username(username):
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
            
        if User.get_user_by_email(email):
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        User.create_user(username, email, password)
        flash('Registration successful! Please login.', 'success')  # Flash notification for successful signup
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)  # Remove username from session
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route("/")
@login_required
def home():
    return render_template("index.html", username=session.get('username'))

@app.route("/predict", methods=["POST"])
@login_required
def predict():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded!"})

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file!"})

    # Validate file format
    allowed_extensions = {"jpg", "jpeg", "png"}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({"error": "Unsupported file format! Please upload a JPG, JPEG, or PNG file."})

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    # Extract GPS location from image
    location = get_gps_data(file_path)

    # Preprocess image for model
    img = Image.open(file_path).resize((224, 224))  # Adjust as per model input
    img_array = np.array(img) / 255.0  # Normalize
    img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension

    # Predict class
    prediction = model.predict(img_array)
    class_label = "Defective" if prediction[0][0] > 0.5 else "Non-Defective"
    confidence = float(prediction[0][0] if class_label == "Defective" else 1 - prediction[0][0])

    # Send email alert if defective
    email_alert_sent = False
    sms_alert_sent = False
    if class_label == "Defective":
        receiver_email = os.getenv('RECEIVER_EMAIL')
        if receiver_email:
            email_alert_sent = send_alert(receiver_email, file_path, location)
        
        phone = request.form.get("phone")
        if phone:
            if location != "GPS data not available":
                # Parse coordinates and create properly formatted Maps link
                lat, lon = [float(coord.strip()) for coord in location.split(',')]
                location_link = f"https://www.google.com/maps?q={lat},{lon}"
            else:
                location_link = "Location not available"
            
            sms_message = f"Alert: Defective railway track detected!\nLocation: {location}\nView on Maps: {location_link}"
            sms_alert_sent = send_sms_alert(phone, sms_message)

    return jsonify({
        "filename": filename, 
        "prediction": class_label, 
        "location": location,
        "confidence": f"{confidence:.2%}",
        "image_url": f"/static/uploads/{filename}",
        "alert_sent": email_alert_sent,
        "sms_alert_sent": sms_alert_sent
    })

# Routes to serve static files
@app.route('/static/<path:path>')
def serve_static(path):
    # Note: Use a proper web server for static files in production
    return app.send_static_file(path)

if __name__ == "__main__":
    app.run(debug=True)