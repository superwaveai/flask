from flask import Flask, request, jsonify, render_template,session,redirect,url_for,flash
import threading
from azure.communication.email import EmailClient, EmailContent, EmailMessage, EmailRecipients, EmailAddress
from azure.core.exceptions import ServiceRequestError
import csv
import io
from flask_socketio import SocketIO
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root@localhost:3306/artillery'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

email_logs = []
# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    campaigns = db.relationship('Campaign', backref='user', lazy=True)

# Campaign model
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Add other fields as needed (sender_address, subject_template, etc.)
    sender_address = db.Column(db.String(255), nullable=False)
    sent_address =db.Column(db.String(255),nullable=False)
    subject_template = db.Column(db.String(255), nullable=False)
    reply_to_address = db.Column(db.String(255), nullable=False)
    connection_string = db.Column(db.String(255), nullable=False)
    
    # csv_file_content = db.Column(db.Text, nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

# Routes for user registration and login
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password,email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user:
            print(f"Entered Username: {username}")
            print(f"Hashed Password from DB: {user.password}")
            print(f"Entered Password: {password}")

            if check_password_hash(user.password, password):
                print('Password is correct. Logging in...')
                session['user_id'] = user.id
                return redirect(url_for('index'))

        print('Invalid username or password.')

    return render_template('login.html')

@app.route('/', methods=['GET','POST'])
def index():
   
    if not session.get('user_id'):
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        sender_address = request.form['sender_address']
        subject_template = request.form['subject_template']
        reply_to_address = request.form['reply_to_address']
        num_threads = int(request.form['num_threads'])
        html_content = request.files['html_content']
        connection_string = request.form['connection_string']
        csv_file = request.files['csv_file']

        contacts = read_csv(csv_file)

        for contact in contacts:
            new_campaign = Campaign(
                user_id=user.id,
                sender_address=sender_address,
                sent_address=contact['Email'],
                subject_template=subject_template,
                reply_to_address=reply_to_address,
                connection_string=connection_string,
                
            )
            db.session.add(new_campaign)

        db.session.commit()

        flash('Campaign created successfully.')

        email_client = EmailClient.from_connection_string(connection_string)

        # Create and start a separate thread for sending emails.
        threads = []
        for contact in contacts:
            if threading.active_count() < num_threads:
                thread = threading.Thread(target=send_email, args=(
                email_client, contact, sender_address, subject_template, reply_to_address, html_content))
                threads.append(thread)
                thread.start()

        for thread in threads:
            thread.join()

        return jsonify({'message': 'Campaign created successfully.'})
    campaigns = user.campaigns
    return render_template('mailer.html',email_logs=email_logs,user=user,campaigns=campaigns)

@socketio.on('connect')
def handle_connect():
    emit_logs()

def emit_logs():
    socketio.emit('update_logs', {'logs': email_logs}, namespace='/')

def read_csv(csv_file):
    stream = io.StringIO(csv_file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.DictReader(stream)
    return list(csv_input)


def send_email(email_client, contact, sender_address, subject_template, reply_to_address, html_content):
    try:
        name = contact["Name"]
        company = contact["Company"]
        email = contact["Email"]
        subject = subject_template.format(Name=name, Company=company)

        # Construct the email message
        email_message = EmailMessage(
            sender=sender_address,
            content=EmailContent(
                subject=subject,
                html=html_content
            ),
            recipients=EmailRecipients(
                to=[EmailAddress(email=email)]
            )
        )

        # Replace 'begin_send' with the appropriate method to send an email
        email_client.send(email_message)

        # print(f"Email sent to {name} at {email}")
        log_message = f"Email sent to {name} at {email}"
        email_logs.append(log_message)
        print(log_message)

        # Emit the updated logs to connected clients
        emit_logs()

    except ServiceRequestError as e:
        # print(f"Failed to send email to {email}: {e}")
        error_message = f"Failed to send email to {email}: {e}"
        email_logs.append(error_message)
        print(error_message)

        # Emit the updated logs to connected clients
        emit_logs()

if __name__ == '__main__':
    app.run(debug=True)
