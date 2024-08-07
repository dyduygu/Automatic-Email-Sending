import os  # İşletim sistemi işlemleri için kullanılır.
import firebase_admin  # Firebase ile etkileşim için kullanılır.
from firebase_admin import credentials, auth, db  # Firebase yetkilendirmesi, kimlik doğrulaması ve veritabanı işlemleri için kullanılır.
from email_validator import validate_email, EmailNotValidError  # E-posta doğrulaması için kullanılır.
from google.auth.exceptions import GoogleAuthError  # Google yetkilendirme hataları için kullanılır.
from flask import Flask, request, render_template, redirect, url_for, flash, session  # Web uygulaması oluşturmak için Flask kullanılır.
import pyrebase  # Firebase ile etkileşim için kullanılır.
import base64  # E-posta oluşturma işlemleri için kullanılır.
from email.mime.multipart import MIMEMultipart  # E-posta oluşturma işlemleri için kullanılır.
from email.mime.text import MIMEText  # E-posta oluşturma işlemleri için kullanılır.
from google.auth.transport.requests import Request  # Google API yetkilendirme işlemleri için kullanılır.
from google.oauth2.credentials import Credentials  # Google API yetkilendirme işlemleri için kullanılır.
from google_auth_oauthlib.flow import InstalledAppFlow  # Google API yetkilendirme işlemleri için kullanılır.
from googleapiclient.discovery import build  # Gmail API ile etkileşim için kullanılır.
from googleapiclient.errors import HttpError  # Google API hataları için kullanılır.
from datetime import datetime  # Zaman işlemleri için kullanılır.


SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Değiştirin

# Firebase Admin SDK ile bağlantıyı başlatın
cred = credentials.Certificate("YOUR JSON") #JSON dosyasını firestore'dan indiriyoruz ve dizinde gerekli yere ekliyoruz
firebase_admin.initialize_app(cred, {
    'databaseURL': 'URL'  # Realtime Database URL'inizi buraya ekleyin
})

firebase_config = {
    'apiKey': "YOUR  API KEY",
    'authDomain': "YOUR DOMAİN NAME",
    'databaseURL': "your url",
    'projectId': "your id",
    'storageBucket': "YOUR STORAGE BUCKET",
    'messagingSenderId': "YOUR İD",
    'appId': "YOUR APP ID"
}

firebase = pyrebase.initialize_app(firebase_config)
auth_pyrebase = firebase.auth()

def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def send_email(to, subject, message_text):
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "client_secret_194479852340-r3usvie8nsro5v4prg010mopq5oecnm9.apps.googleusercontent.com.json", SCOPES
                #indirdiğimiz client secret dosyası
            )
            creds = flow.run_local_server(port=0)
            # Yenilenen kimlik bilgilerini token.json dosyasına kaydeder, proje çalışırken token.json dosyası otomatik oluşturulur
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    try:
         # Gmail API'sini kullanarak e-posta gönderir
        service = build("gmail", "v1", credentials=creds)
        message = create_message('your_email@gmail.com', to, subject, message_text)
        send_message(service, "me", message)
    except HttpError as error:
        print(f"An error occurred: {error}")

def create_message(sender, to, subject, message_text):
    message = MIMEMultipart()
    message['from'] = sender
    message['to'] = to
    message['subject'] = subject
    msg = MIMEText(message_text)
    message.attach(msg)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw}

def send_message(service, user_id, message):
    try:
        message = service.users().messages().send(userId=user_id, body=message).execute()
        print(f"Message Id: {message['id']}")
        return message
    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def register_user(name, email, password):
     # E-posta adresinin geçerli olup olmadığını kontrol eder
    if not is_valid_email(email):
        print("Geçersiz e-posta formatı.")
        return False

    try:# Firebase Authentication kullanarak yeni bir kullanıcı oluşturur
        user = auth.create_user(
            display_name=name,
            email=email,
            password=password
        )
        print(f"Kullanıcı {user.display_name} başarıyla kaydedildi.")
        # Kullanıcının bilgilerini Firebase Realtime Database'e kaydeder
        users_ref = db.reference(f"users/{user.uid}")
        users_ref.set({
            "name": name,
            "email": email,
            "uid": user.uid
        })
        # Kullanıcıya kayıt başarılı olduğuna dair e-posta gönderir
        send_email(email, "Kayıt Başarılı", "Kaydınız başarıyla tamamlandı.")
        return True

    except GoogleAuthError as error:
        # Hata durumunda kullanıcıya kayıt başarısız olduğunu bildirir
        print(f"Kullanıcı kaydı başarısız oldu: {error}")
        return False

def login_user(email, password):
    try:
        # Firebase Authentication kullanarak kullanıcıyı e-posta ve şifresiyle giriş yapar
        user = auth_pyrebase.sign_in_with_email_and_password(email, password)
        # Başarılı giriş durumunda kullanıcıya başarılı girişi doğrulayan bir e-posta gönderir
        print(f"Kullanıcı {email} başarıyla giriş yaptı.")
        send_email(email, "Giriş Başarılı", "Başarıyla giriş yaptınız.")
        return user
    except Exception as error:
        # Hata durumunda kullanıcıya girişin başarısız olduğunu bildirir
        print(f"Giriş başarısız oldu: {error}")
        return None

@app.route('/')
def select_action():
    return render_template('select_action.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if register_user(name, email, password):
            return redirect(url_for('login'))
        else:
            return "Kullanıcı kaydı başarısız oldu."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = login_user(email, password)
        if user:
            return "Giriş başarılı!"
        else:
            return "Giriş başarısız."
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

