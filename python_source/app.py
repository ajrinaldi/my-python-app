import json  # Used to parse and serialize JSON data (for the JWK file and Okta API payloads)
import os  # Used to access environment variables and check file system paths
import re  # Used for regular expression matching to validate emails, employee numbers, and durations
import time  # Used to get the current timestamp for JWT expiration claims
import uuid  # Used to generate a unique identifier (jti) for each JWT assertion
import jwt  # PyJWT library used to sign JSON Web Tokens for Okta API authentication
import requests  # Used to make HTTP POST requests to Okta's OAuth and User APIs
from flask import Flask, redirect, request, url_for, session, render_template_string  # Core Flask web framework utilities
from dotenv import load_dotenv  # Loads environment variables from a local .env file if present

load_dotenv()  # Read variables from .env into the system environment
app = Flask(__name__)  # Initialize the Flask web application instance
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "stable_secret_session_key_for_testing")  # Set secret key to encrypt user session cookies

# ==================== OKTA CONFIGURATION ====================
raw_domain = os.environ.get("OKTA_DOMAIN", "").strip()  # Fetch the Okta domain from environment variables and remove whitespace
OKTA_DOMAIN = raw_domain.replace("https://", "").replace("http://", "").rstrip("/")  # Clean the domain to ensure it has no protocol prefix or trailing slash

# 1. OIDC Web App (for human user login/callback)
CLIENT_ID = os.environ.get("OKTA_CLIENT_ID")  # Client ID for the web app used to log admins into this portal
CLIENT_SECRET = os.environ.get("OKTA_CLIENT_SECRET")  # Client Secret for the OIDC web app
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5001/callback")  # URL Okta redirects back to after user login
SCOPES = "openid profile email"  # OAuth scopes requested during human user login

# 2. API Services App (for creating users via Private JWK)
API_CLIENT_ID = os.environ.get("OKTA_API_CLIENT_ID")  # Client ID for the machine-to-machine Okta API Services app

SECRET_PATH = "/etc/secrets/okta_private_jwk.json"  # Production path for the private key file (e.g., on Render)
jwk_file = SECRET_PATH if os.path.exists(SECRET_PATH) else "okta_private_jwk.json"  # Use production secret path if it exists, otherwise look locally

with open(jwk_file, "r") as f:  # Open the private JSON Web Key (JWK) file in read mode
    JWK_DICT = json.load(f)  # Load the JWK contents into a Python dictionary

SIGNING_KEY = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(JWK_DICT))  # Convert the JWK dictionary into an RSA cryptographic signing key
KEY_ID = JWK_DICT["kid"]  # Extract the Key ID ('kid') so Okta knows which public key matches our signature
# ============================================================


def get_okta_api_token():  # Function to request a machine-to-machine OAuth access token from Okta
    """Signs a short-lived JWT with the private JWK and exchanges it for an Okta API access token."""
    token_url = f"https://{OKTA_DOMAIN}/oauth2/v1/token"  # Okta's organization authorization server token endpoint
    now = int(time.time())  # Current Unix timestamp in seconds

    payload = {  # Define the JWT claims required by Okta for client_credentials assertion
        "aud": token_url,  # Audience: must be the exact Okta token URL
        "iss": API_CLIENT_ID,  # Issuer: the API Services App Client ID
        "sub": API_CLIENT_ID,  # Subject: also the API Services App Client ID
        "iat": now,  # Issued At: current time
        "exp": now + 300,  # Expiration: valid for 5 minutes (300 seconds)
        "jti": str(uuid.uuid4())  # JWT ID: unique random UUID to prevent replay attacks
    }

    client_assertion = jwt.encode(  # Create and cryptographically sign the JWT
        payload,  # The claims dictionary defined above
        SIGNING_KEY,  # Our private RSA key
        algorithm="RS256",  # RSA Signature with SHA-256
        headers={"kid": KEY_ID}  # Include the Key ID in the JWT header
    )

    data = {  # Form-encoded POST body to exchange the signed JWT for an access token
        "grant_type": "client_credentials",  # OAuth grant type for service-to-service auth
        "scope": "okta.users.manage",  # Okta API scope allowing user creation and management
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",  # Standard URN specifying JWT client auth
        "client_assertion": client_assertion  # The signed JWT string
    }

    response = requests.post(token_url, data=data, timeout=15)  # Send POST request to Okta with a 15-second timeout
    if response.status_code != 200:  # Check if Okta rejected the token request
        raise Exception(f"Okta Token Error ({response.status_code}): {response.text} | ClientID sent: {API_CLIENT_ID}")  # Raise an error with details
    return response.json()["access_token"]  # Parse the JSON response and return the Bearer access token
# HTML template for the unauthenticated login landing page
LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="icon" href="https://idenhaus.com" type="image/x-icon">
    <style>
        /* CSS styling for centering the login card, branding logo, and 3D push-button effect */
        body { font-family: 'Montserrat', sans-serif; background: #f8f9fa; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); text-align: center; width: 400px; }
        .brand-logo { display: inline-flex; flex-direction: column; align-items: flex-start; font-weight: bold; line-height: 0.95; margin-bottom: 25px; }
        .brand-top { color: #002855; font-size: 42px; letter-spacing: -1.5px; }
        .brand-bottom { background: #002855; color: white; font-size: 30px; padding: 2px 8px; margin-top: 2px; letter-spacing: -0.5px; }
        h2 { background: #002855; color: white; padding: 20px; margin: 0 -40px 20px -40px; font-size: 20px; }
        .btn { background: #002855; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-weight: bold; text-decoration: none; display: inline-block; border-bottom: 4px solid #00152e; transition: all 0.1s ease; box-shadow: 0 4px 6px rgba(0,0,0,0.15); }
        .btn:hover { background: #001f42; margin-top: 2px; border-bottom-width: 2px; box-shadow: 0 2px 4px rgba(0,0,0,0.15); }
        .btn:active { margin-top: 4px; border-bottom-width: 0px; box-shadow: none; }
    </style>
</head>
<body>
    <div class="card">
        <div class="brand-logo"><div class="brand-top">iden</div><div class="brand-bottom">haus</div></div>
        <h2>OKTA PROVISIONING PORTAL</h2>
        <p style="color:#555; font-size:14px; margin-bottom:30px;">Authentication required to manage users securely.</p>
        <!-- Clicking this link hits the Flask /login route to start the OIDC flow -->
        <a href="/login" class="btn">Log In with Okta</a>
    </div>
</body>
</html>"""

# HTML, CSS, and client-side JavaScript template for the main User Provisioning Dashboard
FORM_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Create An Okta User Profile</title>
    <link rel="icon" href="https://idenhaus.com" type="image/x-icon">
    <style>
        /* Layout, form rows, input error highlighting, disabled states, and status modal popup styles */
        body { font-family: 'Montserrat', sans-serif; background: #f8f9fa; margin: 0; padding: 0; }
        h2 { background: #002855; color: white; padding: 10px 20px; margin: 0; position: relative; display: flex; align-items: center; justify-content: center; min-height: 45px; }
        .brand-header { position: absolute; left: 20px; display: flex; flex-direction: column; align-items: flex-start; font-weight: bold; line-height: 0.95; background: white; padding: 3px 6px; border-radius: 4px; }
        .head-top { color: #002855; font-size: 18px; letter-spacing: -0.8px; }
        .head-bottom { background: #002855; color: white; font-size: 13px; padding: 1px 3px; margin-top: 1px; letter-spacing: -0.3px; }
        .title-text { font-size: 18px; font-weight: bold; letter-spacing: 0.5px; margin-left: 60px; }
        .logout-btn { position: absolute; right: 20px; background: #d32f2f; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 12px; font-weight: bold; }
        .logout-btn:hover { background: #b71c1c; }
        .container { max-width: 650px; margin: 15px auto; background: white; padding: 18px 25px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        .section-title { font-size: 13px; color: #002855; font-weight: bold; margin: 8px 0 5px 0; text-transform: uppercase; letter-spacing: 0.8px; }
        hr { border: 0; border-top: 1px solid #e2e8f0; margin: 10px 0; }
        .form-row { display: flex; gap: 15px; margin-bottom: 8px; }
        .form-group { flex: 1; display: flex; flex-direction: column; }
        label { font-weight: bold; margin-bottom: 3px; font-size: 12px; color: #4a5568; }
        .ast { color: #d32f2f; font-weight: bold; }
        input, select { padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; box-sizing: border-box; font-size: 13px; transition: all 0.2s; }
        input:focus, select:focus { border-color: #002855; outline: none; }
        input.input-error, select.input-error { border: 2px solid #d32f2f !important; background-color: #fff5f5; }
        input:disabled { background-color: #e2e8f0; cursor: not-allowed; }
        .btn-container { padding-top: 5px; }
        .btn { width: 100%; background: #002855; color: white; padding: 10px; border: none; border-radius: 6px; font-size: 15px; font-weight: bold; cursor: pointer; border-bottom: 4px solid #00152e; transition: all 0.1s ease; box-shadow: 0 3px 5px rgba(0,0,0,0.15); display: block; text-align: center; box-sizing: border-box; }
        .btn:hover { background: #001f42; transform: translateY(2px); border-bottom-width: 2px; box-shadow: 0 2px 3px rgba(0,0,0,0.15); }
        .btn:active { transform: translateY(4px); border-bottom-width: 0px; box-shadow: none; }
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; }
        .modal-box { background: white; padding: 25px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.25); }
        .modal-title { font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #002855; text-align: left; }
        .modal-body { margin-bottom: 20px; max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 12px; border-radius: 4px; border: 1px solid #e2e8f0; text-align: left; }
        .modal-btn { background: #002855; color: white; padding: 10px 20px; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; float: right; border-bottom: 3px solid #00152e; }
        .modal-btn:hover { background: #001f42; }
        .modal-btn:active { transform: translateY(2px); border-bottom-width: 0px; }
    </style>
</head>
<body>
    <h2>
        <div class="brand-header"><div class="head-top">iden</div><div class="head-bottom">haus</div></div>
        <span class="title-text">Okta User Provisioning Dashboard</span> <a href="/logout" class="logout-btn">Log Out</a>
    </h2>
    <div class="container">
        <form method="POST" action="/create-user" id="provisionForm" novalidate>
            <div class="section-title">Personal Information</div>
            <div class="form-row">
                <div class="form-group"><label>First Name:<span class="ast">*</span></label><input type="text" name="first_name" id="first_name" value="{{ f.first_name if f else '' }}"></div>
                <div class="form-group"><label>Last Name:<span class="ast">*</span></label><input type="text" name="last_name" id="last_name" value="{{ f.last_name if f else '' }}"></div>
            </div>
            <hr>
            <div class="section-title">Contact & Communication</div>
            <div class="form-row">
                <div class="form-group"><label>Primary Email:<span class="ast">*</span></label><input type="text" name="email" id="email" class="{% if email_error %}input-error{% endif %}" value="{{ f.email if f else '' }}"></div>
                <div class="form-group"><label>Secondary Email (Optional):</label><input type="text" name="second_email" id="second_email" value="{{ f.second_email if f else '' }}"></div>
            </div>
            <hr>
            <div class="section-title">Employment & Role Details</div>
            <div class="form-row">
                <div class="form-group"><label>Title:<span class="ast">*</span></label><input type="text" name="title" id="title" value="{{ f.title if f else '' }}"></div>
                <div class="form-group"><label>Department:<span class="ast">*</span></label><input type="text" name="department" id="department" value="{{ f.department if f else '' }}"></div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>User Type:<span class="ast">*</span></label>
                    <select name="userType" id="userType">
                        <option value="" {% if not f or not f.userType %}selected{% endif %} disabled>Select Type...</option>
                        <option value="Contractor" {% if f and f.userType == 'Contractor' %}selected{% endif %}>Contractor</option>
                        <option value="Employee" {% if f and f.userType == 'Employee' %}selected{% endif %}>Employee</option>
                    </select>
                </div>
                <div class="form-group" id="employeeNumberGroup">
                    <label>Employee Number (9 Digits):<span class="ast" id="empNumAst" style="display: none;">*</span></label>
                    <input type="text" name="employeeNumber" id="employeeNumber" maxlength="9" placeholder="e.g. 123456789" value="{{ f.employeeNumber if f else '' }}">
                </div>
            </div>
            <div id="contractorFieldsBlock" style="display: none;">
                <hr>
                <div class="section-title">Contractor Term Lifecycle Metadata</div>
                <div class="form-row">
                    <div class="form-group"><label>Start Date:<span class="ast">*</span></label><input type="date" name="startDate" id="startDate" value="{{ f.startDate if f else '' }}"></div>
                    <div class="form-group"><label>Contract Duration (Months Only):<span class="ast">*</span></label><input type="text" name="contractDuration" id="contractDuration" placeholder="e.g. 6" value="{{ f.contractDuration if f else '' }}"></div>
                    <div class="form-group"><label>End Date (Auto-Calculated):</label><input type="date" name="endDate" id="endDate" value="{{ f.endDate if f else '' }}" readonly style="background-color: #e2e8f0; cursor: not-allowed;"></div>
                </div>
            </div>
            <p style="font-size:11px; color:#666; font-style:italic; margin-top:8px; margin-bottom:8px;">Fields marked with a red asterisk (<span class="ast">*</span>) are required.</p>
            <div class="btn-container"><button type="submit" class="btn">Create An Okta User Profile</button></div>
        </form>
    </div>
    {% if msg %}
    <div class="modal-overlay" id="statusModal">
        <div class="modal-box">
            <div class="modal-title">{% if 'successfully' in msg %}✔️ Provisioning Success{% else %}❌ Application Alert{% endif %}</div>
            <div class="modal-body">{{ msg | safe }}</div>
            <button class="modal-btn" onclick="document.getElementById('statusModal').style.display='none'">OK</button>
        </div>
    </div>
    {% endif %}
    <script>
    // Grab references to interactive DOM elements
    const userTypeSelect = document.getElementById('userType');
    const employeeNumInput = document.getElementById('employeeNumber');
    const employeeNumberGroup = document.getElementById('employeeNumberGroup');
    const empNumAst = document.getElementById('empNumAst');
    const contractorFieldsBlock = document.getElementById('contractorFieldsBlock');
    const startDateInput = document.getElementById('startDate');
    const durationInput = document.getElementById('contractDuration');
    const endDateInput = document.getElementById('endDate');

    // Toggles visibility, required states, and resets values based on Employee vs Contractor selection
    function handleLayoutStateChange() {
        if (userTypeSelect.value === 'Contractor') {
            employeeNumInput.value = '';  // Clear any employee number
            employeeNumInput.disabled = true;  // Disable input so it isn't submitted
            employeeNumInput.required = false;
            employeeNumInput.classList.remove('input-error');
            empNumAst.style.display = 'none';
            employeeNumberGroup.style.display = 'none';  // Hide employee number field
            contractorFieldsBlock.style.display = 'block';  // Show contractor date/duration fields
            startDateInput.disabled = false;
            durationInput.disabled = false;
        } else if (userTypeSelect.value === 'Employee') {
            employeeNumInput.disabled = false;
            employeeNumInput.required = true;  // Enforce employee number for Employees
            empNumAst.style.display = 'inline';  // Show red required asterisk
            employeeNumberGroup.style.display = 'flex';
            contractorFieldsBlock.style.display = 'none';  // Hide contractor block
            startDateInput.value = '';
            durationInput.value = '';
            endDateInput.value = '';
            startDateInput.disabled = true;
            durationInput.disabled = true;
            startDateInput.classList.remove('input-error');
            durationInput.classList.remove('input-error');
        } else {
            // Default state before a user type is selected
            employeeNumInput.disabled = false;
            employeeNumInput.required = false;
            empNumAst.style.display = 'none';
            employeeNumberGroup.style.display = 'flex';
            contractorFieldsBlock.style.display = 'none';
        }
    }

    // Automatically calculates End Date by adding Contract Duration (months) to Start Date
    function calculateContractLifecycleTimeline() {
        const startVal = startDateInput.value;
        const durationVal = durationInput.value.trim();
        
        // Strip non-numeric characters from duration input
        if (durationVal && !/^\d+$/.test(durationVal)) {
            durationInput.value = durationVal.replace(/\D/g, '');
            return;
        }

        if (!startVal || !durationVal) {
            endDateInput.value = '';
            return;
        }

        const baseDate = new Date(startVal + 'T00:00:00');  // Parse start date in local time
        const monthsToAdd = parseInt(durationVal, 10);
        
        if (isNaN(baseDate.getTime()) || isNaN(monthsToAdd)) {
            endDateInput.value = '';
            return;
        }

        baseDate.setMonth(baseDate.getMonth() + monthsToAdd);  // Add months to start date
        
        // Format resulting date back into YYYY-MM-DD for the HTML date input
        const yyyy = baseDate.getFullYear();
        const mm = String(baseDate.getMonth() + 1).padStart(2, '0');
        const dd = String(baseDate.getDate()).padStart(2, '0');
        
        endDateInput.value = `${yyyy}-${mm}-${dd}`;
    }

    // Attach event listeners for dropdown changes, typing, and initial page load
    userTypeSelect.addEventListener('change', handleLayoutStateChange);
    startDateInput.addEventListener('change', calculateContractLifecycleTimeline);
    durationInput.addEventListener('input', calculateContractLifecycleTimeline);
    window.addEventListener('DOMContentLoaded', handleLayoutStateChange);

    // Client-side form validation before submitting to Flask
    document.getElementById('provisionForm').addEventListener('submit', function(e) {
        let fields = [{id:'first_name'},{id:'last_name'},{id:'email'},{id:'title'},{id:'department'},{id:'userType'}];
        let missing = 0;
        
        // Check all standard required fields
        fields.forEach(f => {
            let el = document.getElementById(f.id);
            if(!el.value.trim()){
                el.classList.add('input-error');
                missing++;
            } else {
                el.classList.remove('input-error');
            }
        });
        
        // Validate 9-digit Employee Number if User Type is Employee
        if (userTypeSelect.value === 'Employee') {
            const empNumValue = employeeNumInput.value.trim();
            if (!empNumValue || !/^\d{9}$/.test(empNumValue)) {
                employeeNumInput.classList.add('input-error');
                missing++;
            } else {
                employeeNumInput.classList.remove('input-error');
            }
        }

        // Validate Contractor dates/duration and ensure no Employee Number exists
        if (userTypeSelect.value === 'Contractor') {
            if (employeeNumInput.value.trim() !== '') {
                employeeNumInput.classList.add('input-error');
                missing++;
            }
            if (!startDateInput.value) {
                startDateInput.classList.add('input-error');
                missing++;
            } else {
                startDateInput.classList.remove('input-error');
            }
            if (!durationInput.value.trim() || !/^\d+$/.test(durationInput.value.trim())) {
                durationInput.classList.add('input-error');
                missing++;
            } else {
                durationInput.classList.remove('input-error');
            }
        }

        // Prevent form submission if any validation checks failed
        if(missing > 0){
            e.preventDefault();
        }
    });
    </script>
</body>
</html>"""


@app.route('/')  # Root URL route
def home():
    if 'access_token' in session:  # If the admin is already logged in
        return redirect(url_for('dashboard'))  # Redirect straight to the provisioning form
    return render_template_string(LOGIN_HTML)  # Otherwise render the login page


@app.route('/login')  # Route triggered when clicking "Log In with Okta"
def login():
    okta_auth_url = (  # Construct the Okta OIDC Authorization Code flow URL
        f"https://{OKTA_DOMAIN}/oauth2/v1/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&scope={SCOPES.replace(' ', '%20')}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state=application_security_test_state"  # CSRF state token
    )
    return redirect(okta_auth_url)  # Redirect the user's browser to Okta's login screen


@app.route('/callback')  # Route Okta redirects back to after successful login
def callback():
    code = request.args.get('code')  # Extract the temporary authorization code from the URL query string
    if not code:  # Return HTTP 400 if no code was provided
        return "Authentication authorization code missing.", 400
    token_url = f"https://{OKTA_DOMAIN}/oauth2/v1/token"  # Okta token exchange endpoint
    data = {  # Payload to exchange the authorization code for an access token
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    response = requests.post(token_url, data=data, timeout=15)  # Perform back-channel token exchange
    if response.status_code != 200:  # Handle token exchange errors
        return f"Token exchange failed: {response.text}", 400

    session['access_token'] = response.json().get('access_token')  # Save the user's access token in the encrypted Flask session
    return redirect(url_for('dashboard'))  # Send the authenticated user to the dashboard
@app.route('/logout')  # Route to log out of the local application
def logout():
    session.clear()  # Wipe all stored session data (including access_token)
    return redirect(url_for('home'))  # Return to the login landing page


@app.route('/dashboard')  # Protected route displaying the user creation form
def dashboard():
    if 'access_token' not in session:  # Enforce authentication check
        return redirect(url_for('home'))  # Kick unauthenticated users back to login
    return render_template_string(FORM_HTML, f=None, msg=None, email_error=False)  # Render blank form


@app.route('/create-user', methods=['POST'])  # Endpoint that processes form submissions
def create_user():
    if 'access_token' not in session:  # Ensure the user has an active session before allowing API calls
        return redirect(url_for('home'))

    form_data = request.form.to_dict()  # Convert submitted form fields into a dictionary
    first_name = form_data.get('first_name', '').strip()  # Extract and trim First Name
    last_name = form_data.get('last_name', '').strip()  # Extract and trim Last Name
    email = form_data.get('email', '').strip()  # Extract and trim Primary Email
    second_email = form_data.get('second_email', '').strip()  # Extract and trim Secondary Email
    title = form_data.get('title', '').strip()  # Extract and trim Job Title
    department = form_data.get('department', '').strip()  # Extract and trim Department
    raw_user_type = form_data.get('userType', '').strip()  # Extract User Type ('Employee' or 'Contractor')
    emp_num = form_data.get('employeeNumber', '').strip()  # Extract 9-digit Employee Number
    start_date = form_data.get('startDate', '').strip()  # Extract Contractor Start Date
    duration_str = form_data.get('contractDuration', '').strip()  # Extract Contractor Duration in months
    end_date = form_data.get('endDate', '').strip()  # Extract auto-calculated Contractor End Date

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):  # Validate basic email syntax on the server
        return render_template_string(FORM_HTML, f=form_data, msg="Invalid primary email format.", email_error=True)

    # Server-side validation for Employee Number and Contractor fields
    if raw_user_type == 'Employee' and (not emp_num or not re.match(r"^\d{9}$", emp_num)):  # Enforce 9-digit number for Employees
        return render_template_string(FORM_HTML, f=form_data, msg="Data Validation Error: Employee Number is required and must be a valid 9-digit number for Employees.", email_error=False)

    if raw_user_type == 'Contractor' and emp_num:  # Block Contractors from having an Employee Number
        return render_template_string(FORM_HTML, f=form_data, msg="Data Validation Error: Contractors cannot have an Employee Number.", email_error=False)

    if raw_user_type == 'Contractor' and (not start_date or not duration_str or not re.match(r"^\d+$", duration_str)):  # Enforce Contractor date & numeric duration
        return render_template_string(FORM_HTML, f=form_data, msg="Data Validation Error: Contractors require a valid Start Date and numeric Contract Duration.", email_error=False)

    user_payload = {  # Construct the base JSON payload expected by Okta's /api/v1/users endpoint
        "profile": {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "login": email,  # Set Okta username/login equal to their primary email
            "title": title,
            "department": department,
            "userType": raw_user_type
        }
    }

    if second_email:  # Include secondEmail only if the optional field was filled out
        user_payload["profile"]["secondEmail"] = second_email

    if raw_user_type == 'Employee':  # Attach employeeNumber attribute for Employees
        user_payload["profile"]["employeeNumber"] = emp_num

    if raw_user_type == 'Contractor':  # Attach custom lifecycle attributes for Contractors
        user_payload["profile"]["contractStartDate"] = start_date
        user_payload["profile"]["contractDurationMonths"] = int(duration_str)  # Cast duration to an integer
        user_payload["profile"]["contractEndDate"] = end_date

    try:
        api_token = get_okta_api_token()  # Obtain a fresh JWT-signed Okta API Bearer token
        headers = {  # Set HTTP headers for the Okta Users API request
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        okta_response = requests.post(  # Call Okta's Create User API in STAGED mode (activate=false)
            f"https://{OKTA_DOMAIN}/api/v1/users?activate=false",
            json=user_payload,
            headers=headers,
            timeout=15
        )
        if okta_response.status_code in (200, 201):  # Check if Okta successfully created the user profile
            return render_template_string(FORM_HTML, f=None, msg="User Profile created successfully in Okta!", email_error=False)
        
        err_json = okta_response.json()  # Parse Okta's error response JSON if creation failed
        summary = err_json.get('errorSummary', 'Unknown error.')  # Get top-level error summary
        causes = ", ".join([c.get('errorSummary', '') for c in err_json.get('errorCauses', [])])  # Extract specific field-level causes
        full_err = f"{summary} ({causes})" if causes else summary  # Combine summary and detailed causes
        return render_template_string(FORM_HTML, f=form_data, msg=f"Okta API Error: {full_err}", email_error=False)  # Re-render form with error modal
    except Exception as e:  # Catch network timeouts, token errors, or unexpected exceptions
        return render_template_string(FORM_HTML, f=form_data, msg=f"Failed to communicate with Okta: {str(e)}", email_error=False)

if __name__ == '__main__':  # Standard Python entry point check
    port = int(os.environ.get("PORT", 5001))  # Read PORT from environment (for Render/cloud hosting) or default to 5001
    app.run(host="0.0.0.0", port=port, debug=True)  # Start the Flask web server listening on all network interfaces
