import jwt
import datetime
import uuid
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)

# CONFIGURATION
app.config['SECRET_KEY'] = 'dev-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False) # Unique ID for the token
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create the DB file
with app.app_context():
    db.create_all()

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "User exists"}), 400
    
    hashed = pbkdf2_sha256.hash(data['password'])
    new_user = User(username=data['username'], password_hash=hashed)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "Registered!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and pbkdf2_sha256.verify(data['password'], user.password_hash):
        # Create Access Token (15 mins)
        access_token = jwt.encode({
            'sub': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({"access_token": access_token})
    
    return jsonify({"msg": "Bad credentials"}), 401

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"msg": "No token"}), 401
    
    try:
        # JWT Decoding happens here
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({"msg": f"Hello {decoded['sub']}, you are authorized!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"msg": "Token expired"}), 401
    except:
        return jsonify({"msg": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(debug=True)