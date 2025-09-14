#virtualenv phy
#phy\Scripts\activate

from flask import Flask, render_template, request,url_for, redirect,session
import google.generativeai as genai
import os
import PyPDF2
from dotenv import load_dotenv



from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


load_dotenv()
# Initialize Flask app
app = Flask(__name__)

# Set up the Google API Key
os.environ["GOOGLE_API_KEY"] =os.getenv("GOOGLE_API_KEY")  # Replace with your actual API key
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-1.5-flash")

app.secret_key = "your_secret_key"   # Change this to something strong
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

with app.app_context():
    db.create_all()

#Routes

@app.route('/')
def home():
    return render_template("landingpage.html")



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('main'))
        else:
            return "Invalid credentials, try again."

    return render_template('login.html')







@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "User already exists. Try logging in!"

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect({{ url_for('signup') }})

    return render_template('signup.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))



@app.route('/main')
def main():
    if 'user_id' in session:   # Only logged-in users can access
        return render_template('main.html')
    else:
        return redirect(url_for('login'))





# functions
def predict_fake_or_real_email_content(text):
    prompt = f"""
    You are an expert in identifying scam messages in text, email etc. Analyze the given text and classify it as:

    - *Real/Legitimate* (Authentic, safe message)
    - *Scam/Fake* (Phishing, fraud, or suspicious message)

    *for the following Text:*
    {text}

    **Return a clear message indicating whether this content is real or a scam. 
    If it is a scam, mention why it seems fraudulent. If it is real, state that it is legitimate.**

    *Only return the classification message and nothing else.*
    Note: Don't return empty or null, you only need to return message for the input text
    """

    response = model.generate_content(prompt)
    return response.text.strip() if response else "Classification failed."


def url_detection(url):
    prompt = f"""
    You are an advanced AI model specializing in URL security classification. Analyze the given URL and classify it as one of the following categories:

    1. Benign**: Safe, trusted, and non-malicious websites such as google.com, wikipedia.org, amazon.com.
    2. Phishing**: Fraudulent websites designed to steal personal information. Indicators include misspelled domains (e.g., paypa1.com instead of paypal.com), unusual subdomains, and misleading content.
    3. Malware**: URLs that distribute viruses, ransomware, or malicious software. Often includes automatic downloads or redirects to infected pages.
    4. Defacement**: Hacked or defaced websites that display unauthorized content, usually altered by attackers.

    *Example URLs and Classifications:*
    - *Benign*: "https://www.microsoft.com/"
    - *Phishing*: "http://secure-login.paypa1.com/"
    - *Malware*: "http://free-download-software.xyz/"
    - *Defacement*: "http://hacked-website.com/"

    *Input URL:* {url}

    *Output Format:*  
    - Return only a string class name
    - Example output for a phishing site:  

    Analyze the URL and return the correct classification (Only name in lowercase such as benign etc.
    Note: Don't return empty or null, at any cost return the corrected class
    """

    response = model.generate_content(prompt)
    return response.text if response else "Detection failed."


# Routes




@app.route('/scam/', methods=['POST'])
def detect_scam():
    extracted_text = ""

    # 1️⃣ Check if user pasted text
    pasted_text = request.form.get("email_text")
    if pasted_text and pasted_text.strip():
        extracted_text = pasted_text.strip()

    # 2️⃣ Otherwise, check if a file is uploaded
    elif 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            if file.filename.endswith('.pdf'):
                pdf_reader = PyPDF2.PdfReader(file)
                extracted_text = " ".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
            elif file.filename.endswith('.txt'):
                extracted_text = file.read().decode("utf-8")
            else:
                return render_template("index.html", message="Invalid file type. Please upload a PDF or TXT file.")
        else:
            return render_template("main.html", message="No file uploaded.")

    # 3️⃣ If nothing provided
    if not extracted_text.strip():
        return render_template("main.html", message="No text or file content provided.")

    # 4️⃣ Run phishing detection
    message = predict_fake_or_real_email_content(extracted_text)
    return render_template("main.html", message=message)



@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(("http://", "https://")):
        return render_template("main.html", message="Invalid URL format.", input_url=url)

    classification = url_detection(url)
    return render_template("main.html", input_url=url, predicted_class=classification)


if __name__ == '__main__':
    app.run(debug=True)