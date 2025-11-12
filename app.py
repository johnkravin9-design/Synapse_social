import os
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, render_template, send_from_directory, session
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
import jwt
import secrets
import random
from datetime import datetime, timedelta, timezone
from functools import wraps
import base64

# Make Google Auth optional for deployment
try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    print("⚠️  Google Auth not available - Google login disabled")
    
    # Create mock classes
    class MockIdToken:
        def verify_oauth2_token(self, token, request, audience=None):
            return None
    id_token = MockIdToken()
    google_requests = None

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///synapse.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration (optional)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('johnkravin9@gmail.com', '')
app.config['MAIL_PASSWORD'] = os.environ.get('bqvhexpqbnztnmww', '')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Mail (with error handling)
try:
    mail = Mail(app)
    MAIL_AVAILABLE = True
except Exception as e:
    MAIL_AVAILABLE = False
    print(f"⚠️  Email not configured: {e}")
    mail = None

#
#
# ==================== DATABASE MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    phone = db.Column(db.String(20), unique=True)
    avatar = db.Column(db.String(10), default='')
    bio = db.Column(db.Text, default='Hey there! I am using Synapse')
    website = db.Column(db.String(255))
    points = db.Column(db.Integer, default=0)
    invites = db.Column(db.Integer, default=0)
    followers_count = db.Column(db.Integer, default=0)
    following_count = db.Column(db.Integer, default=0)
    posts_count = db.Column(db.Integer, default=0)
    email_verified = db.Column(db.Boolean, default=False)
    phone_verified = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    google_id = db.Column(db.String(255), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    stories = db.relationship('Story', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text)
    image = db.Column(db.String(255))
    location = db.Column(db.String(255))
    likes = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    shares = db.Column(db.Integer, default=0)
    saves = db.Column(db.Integer, default=0)
    tagged_users = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    post_likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    post_comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text)
    emoji = db.Column(db.String(10))
    image = db.Column(db.String(255))
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)

class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)

class PhoneVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # like, comment, follow, mention
    content = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class SavedPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    media_url = db.Column(db.String(255))  # Video or image
    media_type = db.Column(db.String(10))  # 'video' or 'image'
    caption = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.relationship('ReelLike', backref='reel', lazy=True)
    comments = db.relationship('ReelComment', backref='reel', lazy=True)

class ReelLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class ReelComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=lambda: datetime.now())

# Add to your existing models
class LiveStream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    stream_key = db.Column(db.String(100), unique=True)
    stream_url = db.Column(db.String(500))
    thumbnail = db.Column(db.String(500))
    is_live = db.Column(db.Boolean, default=False)
    viewers_count = db.Column(db.Integer, default=0)
    max_viewers = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class StreamViewer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stream_id = db.Column(db.Integer, db.ForeignKey('live_stream.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class StreamComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stream_id = db.Column(db.Integer, db.ForeignKey('live_stream.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class StreamLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stream_id = db.Column(db.Integer, db.ForeignKey('live_stream.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class UserPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50))
    interest_score = db.Column(db.Float, default=0.0)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ContentInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content_id = db.Column(db.Integer)
    content_type = db.Column(db.String(20))  # 'post', 'reel', 'story'
    interaction_type = db.Column(db.String(20))  # 'like', 'comment', 'share', 'view'
    duration = db.Column(db.Integer)  # View duration in seconds
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Add to your existing models

import uuid
from datetime import datetime, timezone

class Call(db.Model):
    __tablename__ = 'call'
    
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    caller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    call_type = db.Column(db.String(20), nullable=False)  # 'voice' or 'video'
    status = db.Column(db.String(20), default='ringing')  # 'ringing', 'answered', 'ended', 'missed'
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer, default=0)  # in seconds
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    caller = db.relationship('User', foreign_keys=[caller_id], backref='outgoing_calls')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='incoming_calls')

class CallParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime)
    left_at = db.Column(db.DateTime)
    role = db.Column(db.String(10), default='participant')  # 'caller' or 'participant'

# Add to existing models
class PrivacySettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ghost_mode = db.Column(db.Boolean, default=False)
    last_seen_visibility = db.Column(db.String(20), default='everyone')  # everyone, contacts, nobody
    read_receipts = db.Column(db.Boolean, default=True)
    profile_visibility = db.Column(db.String(20), default='everyone')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class UserViewTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    viewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content_type = db.Column(db.String(20))  # profile, post, story
    content_id = db.Column(db.Integer)
    view_duration = db.Column(db.Integer)  # seconds
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AlgorithmTransparency(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content_id = db.Column(db.Integer)
    content_type = db.Column(db.String(20))
    engagement_score = db.Column(db.Float)
    visibility_score = db.Column(db.Float)
    algorithm_factors = db.Column(db.Text)  # JSON of factors
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ARFilter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    category = db.Column(db.String(50))  # weather, time, sound, face
    trigger_type = db.Column(db.String(50))  # weather_rain, time_night, sound_loud
    filter_data = db.Column(db.Text)  # JSON with filter configuration
    preview_emoji = db.Column(db.String(10))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ARRealityPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text)
    media_url = db.Column(db.String(500))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    ar_filter_id = db.Column(db.Integer, db.ForeignKey('ar_filter.id'))
    visibility_radius = db.Column(db.Integer, default=100)  # meters
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class GeoHotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    name = db.Column(db.String(100))
    vibe_type = db.Column(db.String(50))  # party, chill, creative, food, nature
    intensity = db.Column(db.Float)  # 0-1 scale
    post_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ProfileWidget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    widget_type = db.Column(db.String(50))  # now_playing, mood, supporters, bio_video, nft_gallery
    position_x = db.Column(db.Integer, default=0)
    position_y = db.Column(db.Integer, default=0)
    width = db.Column(db.Integer, default=300)
    height = db.Column(db.Integer, default=200)
    widget_data = db.Column(db.Text)  # JSON with widget-specific data
    is_visible = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class UserMood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mood = db.Column(db.String(50))
    emoji = db.Column(db.String(10))
    intensity = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class NowPlaying(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    song_title = db.Column(db.String(200))
    artist = db.Column(db.String(200))
    album_art = db.Column(db.String(500))
    music_service = db.Column(db.String(50))  # spotify, apple_music, etc.
    is_playing = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Add to existing models
class LifeMoment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text)
    media_url = db.Column(db.String(500))  # 360 photo, video, or image
    voice_note_url = db.Column(db.String(500))
    media_type = db.Column(db.String(20))  # photo_360, video, image, mixed
    mood = db.Column(db.String(50))
    mood_confidence = db.Column(db.Float)  # AI confidence score
    weather = db.Column(db.String(50))
    location_name = db.Column(db.String(200))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    temperature = db.Column(db.Float)
    is_public = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)  # 24-hour stories
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class MomentReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    moment_id = db.Column(db.Integer, db.ForeignKey('life_moment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reaction_type = db.Column(db.String(20))  # video_response, emoji, voice
    video_url = db.Column(db.String(500))  # Mini video reaction
    duration = db.Column(db.Integer)  # seconds
    emoji = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class MoodAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    moment_id = db.Column(db.Integer, db.ForeignKey('life_moment.id'))
    detected_mood = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    facial_expression = db.Column(db.String(50))
    audio_sentiment = db.Column(db.String(50))
    text_sentiment = db.Column(db.String(50))
    analysis_data = db.Column(db.Text)  # JSON with detailed analysis
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ==================== HELPER FUNCTIONS ====================

def generate_verification_code():
    return str(random.randint(100000, 999999))

def send_verification_email(email, code):
    try:
        msg = Message(
            subject='Verify Your Synapse Account',
            recipients=[email],
            html=f'''
            <div style="font-family: Arial, sans-serif; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <h1>Welcome to Synapse!</h1>
                <p style="font-size: 18px;">Your verification code is:</p>
                <h2 style="background: white; color: #667eea; padding: 15px; border-radius: 10px; text-align: center; letter-spacing: 5px;">
                    {code}
                </h2>
                <p>This code expires in 10 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </div>
            '''
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_phone_verification(phone, code):
    print(f"SMS to {phone}: Your Synapse verification code is {code}")
    return True

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1 Try to get token from Authorization header
        header_token = request.headers.get('Authorization')
        raw_token = None

        if header_token:
            parts = header_token.split(" ")
            if len(parts) == 2:
                raw_token = parts[1]

        # 2 If no header token, try cookie token
        if not raw_token:
            raw_token = request.cookies.get('synapse_token')

        # 3 If still no token, reject
        if not raw_token:
            return jsonify({'error': 'Token is missing'}), 401

        # 4 Validate token
        try:
            data = jwt.decode(raw_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            print("Token error:", e)
            return jsonify({'error': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

#from flask_migrate import Migrate

# After initializing db
# db = SQLAlchemy(app)
#migrate = Migrate(app, db)

# ==================== WEB PAGE ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/feed')
def feed():
    return render_template('feed.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/reels')
def reels():
    return render_template('reels.html')

@app.route('/messages')
def messages_page():
    return render_template('messages.html')

@app.route('/notifications')
def notifications_page():
    return render_template('notifications.html')

@app.route('/profile/<username>')
def profile(username):
    # Handle "me" to redirect to current user
    if username == 'me':
        # Try to get current user from session or redirect to login
        token = request.cookies.get('synapse_token')
        if token:
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.get(data['user_id'])
                if user:
                    return redirect(f'/profile/{user.username}')
            except:
                pass
        return redirect('/login')
    
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', profile_user=user)

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/verify-email')
def verify_email_page():
    return render_template('verify_email.html')

@app.route('/saved')
def saved():
    return render_template('saved.html')

@app.route('/create')
def create():
    return render_template('create.html')

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        phone=data.get('phone'),
        avatar=data.get('avatar', '')
    )
    
    db.session.add(user)
    db.session.commit()
    
    code = generate_verification_code()
    verification = EmailVerification(
        user_id=user.id,
        code=code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.session.add(verification)
    db.session.commit()
    
    send_verification_email(user.email, code)
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(days=30)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'message': 'Registration successful! Check your email for verification code.',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'avatar': user.avatar,
            'points': user.points,
            'email_verified': user.email_verified
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user.is_online = True
    user.last_seen = datetime.now(timezone.utc)
    db.session.commit()
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(days=30)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'avatar': user.avatar,
            'points': user.points,
            'invites': user.invites,
            'email_verified': user.email_verified,
            'phone_verified': user.phone_verified
        }
    })

@app.route('/api/auth/verify-email', methods=['POST'])
@token_required
def verify_email(current_user):
    data = request.json
    code = data.get('code')
    
    verification = EmailVerification.query.filter_by(
        user_id=current_user.id,
        code=code
    ).first()
    
    if not verification:
        return jsonify({'error': 'Invalid verification code'}), 400
    
    if datetime.now(timezone.utc) > verification.expires_at:
        return jsonify({'error': 'Verification code expired'}), 400
    
    current_user.email_verified = True
    current_user.points += 50
    db.session.delete(verification)
    db.session.commit()
    
    return jsonify({
        'message': 'Email verified successfully! +50 points',
        'points': current_user.points
    })

@app.route('/api/auth/resend-email-verification', methods=['POST'])
@token_required
def resend_email_verification(current_user):
    EmailVerification.query.filter_by(user_id=current_user.id).delete()
    
    code = generate_verification_code()
    verification = EmailVerification(
        user_id=current_user.id,
        code=code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    db.session.add(verification)
    db.session.commit()
    
    send_verification_email(current_user.email, code)
    
    return jsonify({'message': 'Verification code sent!'})

# ==================== USER ROUTES ====================

@app.route('/api/users/<username>', methods=['GET'])
@token_required
def get_user(current_user, username):
    user = User.query.filter_by(username=username).first_or_404()
    
    is_following = Follow.query.filter_by(
        follower_id=current_user.id,
        following_id=user.id
    ).first() is not None
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'avatar': user.avatar,
        'bio': user.bio,
        'website': user.website,
        'posts_count': user.posts_count,
        'followers_count': user.followers_count,
        'following_count': user.following_count,
        'is_verified': user.is_verified,
        'is_private': user.is_private,
        'is_following': is_following
    })

@app.route('/api/users/<int:user_id>/follow', methods=['POST'])
@token_required
def follow_user(current_user, user_id):
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot follow yourself'}), 400
    
    user = User.query.get_or_404(user_id)
    existing_follow = Follow.query.filter_by(
        follower_id=current_user.id,
        following_id=user_id
    ).first()
    
    if existing_follow:
        db.session.delete(existing_follow)
        current_user.following_count -= 1
        user.followers_count -= 1
        action = 'unfollowed'
    else:
        follow = Follow(follower_id=current_user.id, following_id=user_id)
        db.session.add(follow)
        current_user.following_count += 1
        user.followers_count += 1
        action = 'followed'
        
        notification = Notification(
            user_id=user_id,
            type='follow',
            content=f'{current_user.username} started following you',
            link=f'/profile/{current_user.username}'
        )
        db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'message': f'User {action}',
        'action': actio    })

# ==================== FILE UPLOAD ROUTES ====================
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """Upload image/video and return base64 data URL"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Read file and convert to base64
        file_data = file.read()
        
        # Check file size (e.g., 50MB limit)
        if len(file_data) > 50 * 1024 * 1024:
            return jsonify({'error': 'File too large (max 50MB)'}), 400
            
        file_base64 = base64.b64encode(file_data).decode('utf-8')

        # Determine file type
        file_type = 'image' if file.content_type.startswith('image') else 'video'
        mime_type = file.content_type

        # Create data URL
        data_url = f"data:{mime_type};base64,{file_base64}"

        return jsonify({
            'success': True,
            'data_url': data_url,
            'file_type': file_type,
            'mime_type': mime_type,
            'size': len(file_data)
        })
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/reels/upload', methods=['POST'])
@token_required
def upload_and_create_reel(current_user):
    """Handle file upload and reel creation in one step"""
    
    # Check if file is provided
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Get caption from form data
    caption = request.form.get('caption', '')
    
    try:
        # Process file upload
        file_data = file.read()
        
        if len(file_data) > 50 * 1024 * 1024:
            return jsonify({'error': 'File too large (max 50MB)'}), 400
            
        file_base64 = base64.b64encode(file_data).decode('utf-8')
        file_type = 'image' if file.content_type.startswith('image') else 'video'
        mime_type = file.content_type
        data_url = f"data:{mime_type};base64,{file_base64}"
        
        # Create reel
        reel = Reel(
            user_id=current_user.id,
            media_url=data_url,
            media_type=file_type,
            caption=caption
        )
        
        db.session.add(reel)
        current_user.points += 20
        db.session.commit()
        
        return jsonify({
            'message': 'Reel created successfully!',
            'reel_id': reel.id,
            'points': current_user.points
        }), 201
        
    except Exception as e:
        print(f"Reel creation error: {e}")
        return jsonify({'error': 'Failed to create reel'}), 500

@app.route('/api/debug/upload-test', methods=['POST'])
@token_required
def debug_upload_test(current_user):
    """Test endpoint to see what upload returns"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    file_data = file.read()
    file_base64 = base64.b64encode(file_data).decode('utf-8')
    mime_type = file.content_type
    
    return jsonify({
        'filename': file.filename,
        'content_type': mime_type,
        'data_url_length': len(file_base64),
        'sample_data_url': f"data:{mime_type};base64,{file_base64[:100]}..." if len(file_base64) > 100 else f"data:{mime_type};base64,{file_base64}"
    })

# ==================== FRIEND REQUEST ROUTES ====================

@app.route('/api/friends/request/<int:user_id>', methods=['POST'])
@token_required
def send_friend_request(current_user, user_id):
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot send request to yourself'}), 400

    # Check if request already exists
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=user_id
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Friend request already sent'}), 400

    # Check if reverse request exists
    reverse_request = FriendRequest.query.filter_by(
        sender_id=user_id,
        receiver_id=current_user.id
    ).first()
    
    if reverse_request:
        # Auto-accept if reverse request exists
        reverse_request.status = 'accepted'
        
        # Create mutual follow relationships
        follow1 = Follow(follower_id=current_user.id, following_id=user_id)
        follow2 = Follow(follower_id=user_id, following_id=current_user.id)
        
        db.session.add(follow1)
        db.session.add(follow2)
        
        # Update counts
        current_user.following_count += 1
        current_user.followers_count += 1
        user = User.query.get(user_id)
        user.following_count += 1
        user.followers_count += 1
        
        db.session.commit()
        return jsonify({'message': 'Friend request accepted!'})

    # Create new friend request
    friend_request = FriendRequest(
        sender_id=current_user.id,
        receiver_id=user_id,
        status='pending'
    )
    
    db.session.add(friend_request)
    
    # Create notification
    notification = Notification(
        user_id=user_id,
        type='friend_request',
        content=f'{current_user.username} sent you a friend request',
        link=f'/profile/{current_user.username}'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({'message': 'Friend request sent!'})

@app.route('/api/friends/accept/<int:request_id>', methods=['POST'])
@token_required
def accept_friend_request(current_user, request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    
    if friend_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if friend_request.status != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    friend_request.status = 'accepted'
    
    # Create mutual follow relationships
    follow1 = Follow(follower_id=friend_request.sender_id, following_id=current_user.id)
    follow2 = Follow(follower_id=current_user.id, following_id=friend_request.sender_id)
    
    db.session.add(follow1)
    db.session.add(follow2)
    
    # Update user counts
    sender = User.query.get(friend_request.sender_id)
    sender.following_count += 1
    current_user.following_count += 1
    sender.followers_count += 1
    current_user.followers_count += 1
    
    db.session.commit()
    
    return jsonify({'message': 'Friend request accepted!'})

@app.route('/api/friends/reject/<int:request_id>', methods=['POST'])
@token_required
def reject_friend_request(current_user, request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    
    if friend_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    friend_request.status = 'rejected'
    db.session.commit()
    
    return jsonify({'message': 'Friend request rejected'})

@app.route('/api/friends/requests', methods=['GET'])
@token_required
def get_friend_requests(current_user):
    requests = FriendRequest.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).all()
    
    requests_data = []
    for req in requests:
        sender = User.query.get(req.sender_id)
        requests_data.append({
            'id': req.id,
            'sender': {
                'id': sender.id,
                'username': sender.username,
                'avatar': sender.avatar
            },
            'created_at': req.created_at.isoformat()
        })
    
    return jsonify({'requests': requests_data})

# ==================== PUBLIC ROUTES (No Auth Required) ====================

@app.route('/api/public/posts', methods=['GET'])
def get_public_posts():
    """Get posts without authentication (for landing page)"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    posts = Post.query.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    posts_data = []
    for post in posts.items:
        user = User.query.get(post.user_id)
        posts_data.append({
            'id': post.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar,
                'is_verified': getattr(user, 'is_verified', False)
            },
            'content': post.content,
            'image': post.image,
            'location': post.location,
            'likes': post.likes,
            'comments': post.comments_count,
            'shares': post.shares,
            'timestamp': post.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'posts': posts_data,
        'has_next': posts.has_next
    })

@app.route('/api/public/stories', methods=['GET'])
def get_public_stories():
    """Get stories without authentication"""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    stories = Story.query.filter(Story.created_at >= cutoff).order_by(Story.created_at.desc()).all()
    
    stories_data = []
    for story in stories:
        user = User.query.get(story.user_id)
        stories_data.append({
            'id': story.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'content': story.content,
            'emoji': story.emoji,
            'image': getattr(story, 'image', None),  # Safe get
            'views': story.views,
            'timestamp': story.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'stories': stories_data})

# ==================== POST ROUTES ====================

@app.route('/api/posts', methods=['GET'])
@token_required
def get_posts(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    posts = Post.query.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    posts_data = []
    for post in posts.items:
        user = User.query.get(post.user_id)
        is_liked = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
        is_saved = SavedPost.query.filter_by(user_id=current_user.id, post_id=post.id).first() is not None
        
        posts_data.append({
            'id': post.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar,
                'is_verified': user.is_verified
            },
            'content': post.content,
            'image': post.image,
            'location': post.location,
            'likes': post.likes,
            'comments': post.comments_count,
            'shares': post.shares,
            'saves': post.saves,
            'liked': is_liked,
            'saved': is_saved,
            'taggedUsers': post.tagged_users.split(',') if post.tagged_users else [],
            'timestamp': post.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'posts': posts_data,
        'has_next': posts.has_next,
        'has_prev': posts.has_prev,
        'page': page,
        'total_pages': posts.pages
    })

@app.route('/api/posts', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.json
    
    post = Post(
        user_id=current_user.id,
        content=data.get('content'),
        image=data.get('image'),
        location=data.get('location'),
        tagged_users=','.join(data.get('taggedUsers', []))
    )
    
    db.session.add(post)
    current_user.points += 10
    current_user.posts_count += 1
    db.session.commit()
    
    socketio.emit('new_post', {
        'id': post.id,
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'avatar': current_user.avatar
        },
        'content': post.content,
        'timestamp': 'Just now'
    })
    
    return jsonify({
        'message': 'Post created!',
        'post_id': post.id,
        'points': current_user.points
    }), 201

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    current_user.posts_count -= 1
    db.session.delete(post)
    db.session.commit()
    
    return jsonify({'message': 'Post deleted'})

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required
def like_post(current_user, post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        post.likes -= 1
        action = 'unliked'
    else:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        post.likes += 1
        action = 'liked'
        
        if post.user_id != current_user.id:
            notification = Notification(
                user_id=post.user_id,
                type='like',
                content=f'{current_user.username} liked your post',
                link=f'/p/{post_id}'
            )
            db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'message': f'Post {action}',
        'likes': post.likes
    })

@app.route('/api/posts/<int:post_id>/save', methods=['POST'])
@token_required
def save_post(current_user, post_id):
    post = Post.query.get_or_404(post_id)
    existing_save = SavedPost.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_save:
        db.session.delete(existing_save)
        post.saves -= 1
        action = 'unsaved'
    else:
        save = SavedPost(user_id=current_user.id, post_id=post_id)
        db.session.add(save)
        post.saves += 1
        action = 'saved'
    
    db.session.commit()
    
    return jsonify({
        'message': f'Post {action}',
        'saves': post.saves
    })

@app.route('/api/posts/<int:post_id>/comments', methods=['GET'])
@token_required
def get_comments(current_user, post_id):
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    
    comments_data = []
    for comment in comments:
        user = User.query.get(comment.user_id)
        comments_data.append({
            'id': comment.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'content': comment.content,
            'likes': comment.likes,
            'timestamp': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'comments': comments_data})

@app.route('/api/posts/<int:post_id>/share', methods=['POST'])
@token_required
def share_post(current_user, post_id):
    post = Post.query.get_or_404(post_id)
    post.shares += 1
    
    if post.user_id != current_user.id:
        notification = Notification(
            user_id=post.user_id,
            type='share',
            content=f'{current_user.username} shared your post',
            link=f'/p/{post_id}'
        )
        db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Post shared',
        'shares': post.shares
    })

@app.route('/api/comments/<int:comment_id>/like', methods=['POST'])
@token_required
def like_comment(current_user, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # For simplicity, we'll just increment the count
    # In production, create a CommentLike table
    comment.likes += 1
    db.session.commit()
    
    return jsonify({
        'message': 'Comment liked',
        'likes': comment.likes
    })

# ==================== STORY ROUTES ====================

@app.route('/api/stories', methods=['GET'])
@token_required
def get_stories(current_user):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    stories = Story.query.filter(Story.created_at >= cutoff).order_by(Story.created_at.desc()).all()
    
    stories_data = []
    for story in stories:
        user = User.query.get(story.user_id)
        stories_data.append({
            'id': story.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'content': story.content,
            'emoji': story.emoji,
            'image': story.image,
            'views': story.views,
            'timestamp': story.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'stories': stories_data})

@app.route('/api/stories', methods=['POST'])
@token_required
def create_story(current_user):
    data = request.json
    
    story = Story(
        user_id=current_user.id,
        content=data.get('content'),
        emoji=data.get('emoji'),
        image=data.get('image'),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
    )
    
    db.session.add(story)
    current_user.points += 5
    db.session.commit()
    
    socketio.emit('new_story', {
        'user': current_user.username,
        'avatar': current_user.avatar
    })
    
    return jsonify({
        'message': 'Story posted!',
        'story_id': story.id,
        'points': current_user.points
    }), 201

# ==================== MESSAGES ROUTES ====================

@app.route('/api/messages/conversations', methods=['GET'])
@token_required
def get_conversations(current_user):
    # Get unique conversations
    sent = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
    received = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
    
    user_ids = set([r[0] for r in sent] + [r[0] for r in received])
    
    conversations = []
    for user_id in user_ids:
        user = User.query.get(user_id)
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at.desc()).first()
        
        unread_count = Message.query.filter_by(
            sender_id=user_id,
            receiver_id=current_user.id,
            is_read=False
        ).count()
        
        conversations.append({
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar,
                'is_online': user.is_online
            },
            'last_message': {
                'content': last_message.content,
                'timestamp': last_message.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } if last_message else None,
            'unread_count': unread_count
        })
    
    return jsonify({'conversations': conversations})

@app.route('/api/messages/<int:user_id>', methods=['GET'])
@token_required
def get_messages(current_user, user_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()
    
    # Mark messages as read
    Message.query.filter_by(
        sender_id=user_id,
        receiver_id=current_user.id,
        is_read=False
    ).update({'is_read': True})
    db.session.commit()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'content': msg.content,
            'is_read': msg.is_read,
            'timestamp': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'messages': messages_data})

@app.route('/api/messages/<int:user_id>', methods=['POST'])
@token_required
def send_message(current_user, user_id):
    data = request.json
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=user_id,
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Send via WebSocket
    socketio.emit('new_message', {
        'id': message.id,
        'sender_id': current_user.id,
        'sender_username': current_user.username,
        'sender_avatar': current_user.avatar,
        'content': message.content,
        'timestamp': 'Just now'
    }, room=f'user_{user_id}')
    
    return jsonify({
        'message': 'Message sent!',
        'message_id': message.id
    })

# ==================== NOTIFICATIONS ROUTES ====================

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    try:
        notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(Notification.created_at.desc()).limit(50).all()
        
        notifications_data = []
        for notif in notifications:
            notifications_data.append({
                'id': notif.id,
                'type': notif.type,
                'content': notif.content,
                'link': notif.link,
                'is_read': notif.is_read,
                'timestamp': notif.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify({'notifications': notifications_data})
    except Exception as e:
        return jsonify({'notifications': []})

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
@token_required
def mark_notification_read(current_user, notif_id):
    notification = Notification.query.get_or_404(notif_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'message': 'Notification marked as read'})

@app.route('/api/notifications/read-all', methods=['POST'])
@token_required
def mark_all_notifications_read(current_user):
    Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).update({'is_read': True})
    db.session.commit()
    
    return jsonify({'message': 'All notifications marked as read'})

# ==================== EXPLORE ROUTES ====================

@app.route('/api/explore', methods=['GET'])
@token_required
def explore_posts(current_user):
    # Get trending posts (high engagement in last 24 hours)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    posts = Post.query.filter(Post.created_at >= cutoff).order_by(
        (Post.likes + Post.comments_count * 2 + Post.shares * 3).desc()
    ).limit(30).all()
    
    posts_data = []
    for post in posts:
        user = User.query.get(post.user_id)
        posts_data.append({
            'id': post.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'image': post.image,
            'likes': post.likes,
            'comments': post.comments_count
        })
    
    return jsonify({'posts': posts_data})

@app.route('/api/search', methods=['GET'])
@token_required
def search(current_user):
    query = request.args.get('q', '')
    
    # Search users
    users = User.query.filter(
        User.username.ilike(f'%{query}%')
    ).limit(20).all()
    
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'bio': user.bio,
            'is_verified': user.is_verified,
            'followers_count': user.followers_count
        })
    
    return jsonify({'users': users_data})

# ==================== REELS ROUTES ====================

# FIXED: Remove duplicate route or rename it
# If you need file upload, use a different endpoint name:
@app.route('/api/reels/upload', methods=['POST'])
def upload_reel():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    # Make sure uploads directory exists
    os.makedirs('uploads', exist_ok=True)
    file.save(os.path.join('uploads', filename))

    return jsonify({'success': True, 'filename': filename})

@app.route('/api/reels/<int:reel_id>/like', methods=['POST'])
@token_required
def like_reel(current_user, reel_id):
    reel = Reel.query.get(reel_id)
    if not reel:
        return jsonify({"error": "Reel not found"}), 404
    existing_like = ReelLike.query.filter_by(reel_id=reel.id, user_id=current_user.id).first()
    if existing_like:
        db.session.delete(existing_like)  # Unlike
    else:
        db.session.add(ReelLike(reel_id=reel.id, user_id=current_user.id))
    db.session.commit()
    return jsonify({"message": "Like toggled"})

@app.route('/api/reels', methods=['GET'])
@token_required
def get_reels(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 10

    reels = Reel.query.order_by(Reel.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    reels_data = []
    for reel in reels.items:
        user = User.query.get(reel.user_id)
        reels_data.append({
            'id': reel.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'media_url': reel.media_url,
            'media_type': reel.media_type,
            'caption': reel.caption,
            'likes_count': len(reel.likes),
            'comments_count': len(reel.comments),
            'created_at': reel.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify({
        'reels': reels_data,
        'has_next': reels.has_next
    })

@app.route('/api/reels', methods=['POST'])
@token_required
def create_reel(current_user):
    data = request.json

    media_url = data.get('media_url') or data.get('video_url') or data.get('image')
    caption = data.get('caption', '')
    media_type = data.get('media_type', '')

    # Auto-detect media type if not provided
    if not media_type:
        if media_url.startswith('data:video') or 'video' in media_url.lower():
            media_type = 'video'
        elif media_url.startswith('data:image') or 'image' in media_url.lower():
            media_type = 'image'
        else:
            # Assume it's an emoji or text content
            media_type = 'emoji'

    if not media_url:
        return jsonify({'error': 'Media URL is required'}), 400

    reel = Reel(
        user_id=current_user.id,
        media_url=media_url,
        media_type=media_type,
        caption=caption
    )

    db.session.add(reel)
    current_user.points += 20
    db.session.commit()

    return jsonify({
        'message': 'Reel created!',
        'reel_id': reel.id,
        'points': current_user.points,
        'media_type': media_type  # Return media type to frontend
    }), 201

@app.route('/api/reels/<int:reel_id>/comment', methods=['POST'])
@token_required
def comment_reel(current_user, reel_id):
    data = request.get_json()
    text = data.get('text')
    if not text:
        return jsonify({"error": "Comment text is required"}), 400
        
    comment = ReelComment(reel_id=reel_id, user_id=current_user.id, text=text)
    db.session.add(comment)
    db.session.commit()
    return jsonify({"message": "Comment added"})

@app.route('/api/reels/<int:reel_id>/share', methods=['POST'])
@token_required
def share_reel(current_user, reel_id):
    original = Reel.query.get(reel_id)
    if not original:
        return jsonify({"error": "Reel not found"}), 404
        
    # Create a shared reel entry or increment share count
    shared_reel = Reel(
        user_id=current_user.id, 
        media_url=original.media_url, 
        media_type=original.media_type, 
        caption=original.caption
    )
    db.session.add(shared_reel)
    db.session.commit()
    return jsonify({"message": "Reel shared"})

# ==================== LIVE STREAMING ROUTES ====================

@app.route('/api/live/start', methods=['POST'])
@token_required
def start_live_stream(current_user):
    """Start a new live stream"""
    data = request.json
    title = data.get('title', 'My Live Stream')
    description = data.get('description', '')

    # Generate unique stream key
    stream_key = secrets.token_urlsafe(16)

    # Check if user already has an active stream
    active_stream = LiveStream.query.filter_by(
        user_id=current_user.id,
        is_live=True
    ).first()

    if active_stream:
        return jsonify({'error': 'You already have an active stream'}), 400

    stream = LiveStream(
        user_id=current_user.id,
        title=title,
        description=description,
        stream_key=stream_key,
        stream_url=f"rtmp://localhost/live/{stream_key}",  # Change to your RTMP server
        is_live=True,
        started_at=datetime.now(timezone.utc)
    )

    db.session.add(stream)
    
    # Notify followers
    followers = Follow.query.filter_by(following_id=current_user.id).all()
    for follow in followers:
        notification = Notification(
            user_id=follow.follower_id,
            type='live_stream',
            content=f'{current_user.username} started a live stream: {title}',
            link=f'/live/{current_user.username}'
        )
        db.session.add(notification)

    db.session.commit()

    # Broadcast via WebSocket
    socketio.emit('live_stream_started', {
        'stream_id': stream.id,
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'avatar': current_user.avatar
        },
        'title': title,
        'description': description,
        'viewers_count': 0,
        'started_at': stream.started_at.isoformat()
    })

    return jsonify({
        'message': 'Live stream started!',
        'stream_id': stream.id,
        'stream_key': stream_key,
        'stream_url': stream.stream_url
    })

@app.route('/api/live/end/<int:stream_id>', methods=['POST'])
@token_required
def end_live_stream(current_user, stream_id):
    """End a live stream"""
    stream = LiveStream.query.get_or_404(stream_id)

    if stream.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if not stream.is_live:
        return jsonify({'error': 'Stream is not live'}), 400

    stream.is_live = False
    stream.ended_at = datetime.now(timezone.utc)

    # Remove all viewers
    StreamViewer.query.filter_by(stream_id=stream_id).delete()

    db.session.commit()

    # Broadcast via WebSocket
    socketio.emit('live_stream_ended', {
        'stream_id': stream_id,
        'user_id': current_user.id
    })

    return jsonify({'message': 'Live stream ended'})

@app.route('/api/live/join/<int:stream_id>', methods=['POST'])
@token_required
def join_live_stream(current_user, stream_id):
    """Join a live stream as viewer"""
    stream = LiveStream.query.get_or_404(stream_id)

    if not stream.is_live:
        return jsonify({'error': 'Stream is not live'}), 400

    # Check if already viewing
    existing_viewer = StreamViewer.query.filter_by(
        stream_id=stream_id,
        user_id=current_user.id
    ).first()

    if not existing_viewer:
        viewer = StreamViewer(stream_id=stream_id, user_id=current_user.id)
        db.session.add(viewer)
        
        # Update viewer count
        stream.viewers_count = StreamViewer.query.filter_by(stream_id=stream_id).count()
        if stream.viewers_count > stream.max_viewers:
            stream.max_viewers = stream.viewers_count
        
        db.session.commit()

    # Broadcast viewer count update
    socketio.emit('viewer_count_update', {
        'stream_id': stream_id,
        'viewers_count': stream.viewers_count
    }, room=f'stream_{stream_id}')

    return jsonify({
        'message': 'Joined live stream',
        'viewers_count': stream.viewers_count
    })

@app.route('/api/live/leave/<int:stream_id>', methods=['POST'])
@token_required
def leave_live_stream(current_user, stream_id):
    """Leave a live stream"""
    viewer = StreamViewer.query.filter_by(
        stream_id=stream_id,
        user_id=current_user.id
    ).first()

    if viewer:
        db.session.delete(viewer)
        
        # Update viewer count
        stream = LiveStream.query.get(stream_id)
        if stream:
            stream.viewers_count = StreamViewer.query.filter_by(stream_id=stream_id).count()
            db.session.commit()

            # Broadcast viewer count update
            socketio.emit('viewer_count_update', {
                'stream_id': stream_id,
                'viewers_count': stream.viewers_count
            }, room=f'stream_{stream_id}')

    return jsonify({'message': 'Left live stream'})

@app.route('/api/live/streams', methods=['GET'])
@token_required
def get_live_streams(current_user):
    """Get all active live streams"""
    active_streams = LiveStream.query.filter_by(is_live=True).order_by(
        LiveStream.viewers_count.desc()
    ).all()

    streams_data = []
    for stream in active_streams:
        user = User.query.get(stream.user_id)
        streams_data.append({
            'id': stream.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'title': stream.title,
            'description': stream.description,
            'viewers_count': stream.viewers_count,
            'max_viewers': stream.max_viewers,
            'started_at': stream.started_at.isoformat(),
            'thumbnail': stream.thumbnail,
            'is_live': stream.is_live
        })

    return jsonify({'streams': streams_data})

@app.route('/api/live/<int:stream_id>/comments', methods=['GET'])
@token_required
def get_stream_comments(current_user, stream_id):
    """Get comments for a live stream"""
    comments = StreamComment.query.filter_by(stream_id=stream_id).order_by(
        StreamComment.created_at.asc()
    ).all()

    comments_data = []
    for comment in comments:
        user = User.query.get(comment.user_id)
        comments_data.append({
            'id': comment.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'message': comment.message,
            'timestamp': comment.created_at.strftime('%H:%M:%S')
        })

    return jsonify({'comments': comments_data})

@app.route('/api/live/<int:stream_id>/comment', methods=['POST'])
@token_required
def post_stream_comment(current_user, stream_id):
    """Post a comment to live stream"""
    data = request.json
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    stream = LiveStream.query.get_or_404(stream_id)
    if not stream.is_live:
        return jsonify({'error': 'Stream is not live'}), 400

    comment = StreamComment(
        stream_id=stream_id,
        user_id=current_user.id,
        message=message
    )

    db.session.add(comment)
    db.session.commit()

    # Broadcast comment via WebSocket
    socketio.emit('new_stream_comment', {
        'id': comment.id,
        'stream_id': stream_id,
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'avatar': current_user.avatar
        },
        'message': message,
        'timestamp': comment.created_at.strftime('%H:%M:%S')
    }, room=f'stream_{stream_id}')

    return jsonify({'message': 'Comment posted'})

@app.route('/api/live/<int:stream_id>/like', methods=['POST'])
@token_required
def like_stream(current_user, stream_id):
    """Like a live stream"""
    stream = LiveStream.query.get_or_404(stream_id)
    if not stream.is_live:
        return jsonify({'error': 'Stream is not live'}), 400

    existing_like = StreamLike.query.filter_by(
        stream_id=stream_id,
        user_id=current_user.id
    ).first()

    if existing_like:
        db.session.delete(existing_like)
        action = 'unliked'
    else:
        like = StreamLike(stream_id=stream_id, user_id=current_user.id)
        db.session.add(like)
        action = 'liked'

    db.session.commit()

    # Broadcast like count update
    like_count = StreamLike.query.filter_by(stream_id=stream_id).count()
    socketio.emit('stream_like_update', {
        'stream_id': stream_id,
        'like_count': like_count,
        'action': action,
        'user': current_user.username
    }, room=f'stream_{stream_id}')

    return jsonify({
        'message': f'Stream {action}',
        'like_count': like_count
    })
#===========================  live & call route  ======================

@app.route('/live')
def live_page():
    return render_template('live.html')

@app.route('/call')
def call_page():
    return render_template('call.html')

@socketio.on('test_ping')
def handle_test_ping(data):
    print('Test ping received:', data)
    emit('test_pong', {'message': 'Real-time working!'})

# ==================== SAVED POSTS ROUTES ====================

@app.route('/api/saved', methods=['GET'])
@token_required
def get_saved_posts(current_user):
    saved = SavedPost.query.filter_by(user_id=current_user.id).order_by(
        SavedPost.created_at.desc()
    ).all()
    
    posts_data = []
    for save in saved:
        post = Post.query.get(save.post_id)
        if post:
            user = User.query.get(post.user_id)
            posts_data.append({
                'id': post.id,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar
                },
                'content': post.content,
                'image': post.image,
                'likes': post.likes,
                'comments': post.comments_count
            })
    
    return jsonify({'posts': posts_data})

@app.route('/moments/feed')
def moments_feed():
    """Life moments feed page"""
    return render_template('moments_feed.html')

@app.route('/create/moment')
def create_moment():
    """Create life moment page"""
    return render_template('create_moment.html')

@app.route('/privacy/settings')
def privacy_settings():
    """Privacy settings page"""
    return render_template('privacy_settings.html')

# ==================== SETTINGS ROUTES ====================

@app.route('/api/settings/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    data = request.json
    
    if 'username' in data and data['username'] != current_user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already taken'}), 400
        current_user.username = data['username']
    
    if 'bio' in data:
        current_user.bio = data['bio']
    
    if 'website' in data:
        current_user.website = data['website']
    
    if 'avatar' in data:
        current_user.avatar = data['avatar']
    
    if 'is_private' in data:
        current_user.is_private = data['is_private']
    
    db.session.commit()
    
    return jsonify({'message': 'Profile updated successfully'})

@app.route('/api/settings/password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.json
    
    if not check_password_hash(current_user.password_hash, data['old_password']):
        return jsonify({'error': 'Invalid old password'}), 400
    
    current_user.password_hash = generate_password_hash(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'})

#=====j====j=========profile routes =====================
@app.route('/profile/me')
def profile_me():
    token = request.cookies.get('synapse_token')
    if not token:
        return redirect('/login')
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        if user:
            return redirect(f'/profile/{user.username}')
    except Exception as e:
        print(f"Token error: {e}")
    
    return redirect('/login')

# ================================   AI CONTENT  =========================

# Add to app.py
import requests
import os

# AI Configuration
AI_API_KEY = os.environ.get('AI_API_KEY', 'your-ai-api-key')
AI_BASE_URL = 'https://api.openai.com/v1'  # or your preferred AI service

def analyze_content_sentiment(content):
    """Analyze content sentiment and safety"""
    try:
        # For production, integrate with OpenAI, Google AI, or Hugging Face
        # This is a simplified version using a free sentiment analysis API
        
        # Simple rule-based sentiment analysis (replace with actual AI in production)
        positive_words = ['amazing', 'great', 'love', 'awesome', 'fantastic', 'excellent', 'happy', 'good', 'beautiful', 'wonderful']
        negative_words = ['bad', 'hate', 'terrible', 'awful', 'horrible', 'sad', 'angry', 'dislike', 'worst']
        
        content_lower = content.lower()
        positive_score = sum(1 for word in positive_words if word in content_lower)
        negative_score = sum(1 for word in negative_words if word in content_lower)
        
        if positive_score > negative_score:
            sentiment = 'positive'
            confidence = min(0.95, positive_score / 10)
        elif negative_score > positive_score:
            sentiment = 'negative'
            confidence = min(0.95, negative_score / 10)
        else:
            sentiment = 'neutral'
            confidence = 0.5
            
        # Content safety check
        inappropriate_words = ['violence', 'harassment', 'abuse', 'spam', 'scam']  # Expand this list
        is_safe = not any(word in content_lower for word in inappropriate_words)
        
        return {
            'sentiment': sentiment,
            'confidence': confidence,
            'is_safe': is_safe,
            'positive_score': positive_score,
            'negative_score': negative_score
        }
    except Exception as e:
        print(f"AI analysis error: {e}")
        return {
            'sentiment': 'neutral',
            'confidence': 0.5,
            'is_safe': True,
            'positive_score': 0,
            'negative_score': 0
        }

@app.route('/api/ai/analyze-content', methods=['POST'])
@token_required
def analyze_content(current_user):
    """AI-powered content analysis"""
    data = request.json
    content = data.get('content', '')
    
    analysis = analyze_content_sentiment(content)
    
    return jsonify({
        'analysis': analysis,
        'suggestions': generate_content_suggestions(analysis)
    })

def generate_content_suggestions(analysis):
    """Generate content improvement suggestions"""
    suggestions = []
    
    if analysis['sentiment'] == 'negative' and analysis['confidence'] > 0.7:
        suggestions.append("Consider using more positive language to engage your audience")
    
    if analysis['positive_score'] == 0 and analysis['negative_score'] == 0:
        suggestions.append("Add more descriptive words to make your content more engaging")
    
    if not analysis['is_safe']:
        suggestions.append("Your content may violate community guidelines. Please review.")
    
    return suggestions

#  <<<<<<<<<<<<<<<<<<<<<  AI CAPTION GENERATOR  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

@app.route('/api/ai/generate-caption', methods=['POST'])
@token_required
def generate_caption(current_user):
    """AI-generated captions based on content"""
    data = request.json
    content = data.get('content', '')
    image_data = data.get('image_data', '')
    mood = data.get('mood', 'neutral')
    
    # Analyze content sentiment to tailor captions
    analysis = analyze_content_sentiment(content)
    
    # Caption templates based on mood and sentiment
    caption_templates = {
        'positive': [
            "Feeling amazing! {} ✨",
            "So grateful for this moment! {} 🌟",
            "Living my best life! {} 💫",
            "This made my day! {} 😊",
            "Absolutely loving this! {} ❤️"
        ],
        'neutral': [
            "Check this out! {} 📸",
            "Sharing something cool! {} 🔥",
            "Thoughts on this? {} 💭",
            "What do you think? {} 🤔",
            "Just sharing! {} 👀"
        ],
        'creative': [
            "Creating magic! {} 🎨",
            "Art in motion! {} ✨",
            "Expressing myself! {} 🎭",
            "Creative vibes! {} 🌈",
            "Imagination unleashed! {} 💫"
        ]
    }
    
    # Select appropriate templates
    templates = caption_templates.get(mood, caption_templates['neutral'])
    
    # Generate multiple caption options
    captions = []
    for template in templates[:5]:  # Limit to 5 options
        if content:
            caption = template.format(content)
        else:
            caption = template.format("")
        captions.append(caption)
    
    # Add some AI-powered creative captions
    creative_captions = [
        "Making memories that last forever! 📸",
        "Capturing the moment, creating stories! ✨",
        "Life's beautiful moments deserve to be shared! 🌟",
        "Every picture tells a story, what's yours? 📖",
        "Creating waves of inspiration! 🌊"
    ]
    
    captions.extend(creative_captions[:3])
    
    return jsonify({
        'captions': captions,
        'suggested': captions[0] if captions else "Share your moment! 📸",
        'mood': mood,
        'sentiment': analysis['sentiment']
    })

# ¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥  AIH HASHTAG SUGGESTION  ¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥

@app.route('/api/ai/generate-caption', methods=['POST'])
@token_required
def generate_caption_v2(current_user):
    """AI-generated captions based on content"""
    data = request.json
    content = data.get('content', '')
    image_data = data.get('image_data', '')
    mood = data.get('mood', 'neutral')
    
    # Analyze content sentiment to tailor captions
    analysis = analyze_content_sentiment(content)
    
    # Caption templates based on mood and sentiment
    caption_templates = {
        'positive': [
            "Feeling amazing! {} ✨",
            "So grateful for this moment! {} 🌟",
            "Living my best life! {} 💫",
            "This made my day! {} 😊",
            "Absolutely loving this! {} ❤️"
        ],
        'neutral': [
            "Check this out! {} 📸",
            "Sharing something cool! {} 🔥",
            "Thoughts on this? {} 💭",
            "What do you think? {} 🤔",
            "Just sharing! {} 👀"
        ],
        'creative': [
            "Creating magic! {} 🎨",
            "Art in motion! {} ✨",
            "Expressing myself! {} 🎭",
            "Creative vibes! {} 🌈",
            "Imagination unleashed! {} 💫"
        ]
    }
    
    # Select appropriate templates
    templates = caption_templates.get(mood, caption_templates['neutral'])
    
    # Generate multiple caption options
    captions = []
    for template in templates[:5]:  # Limit to 5 options
        if content:
            caption = template.format(content)
        else:
            caption = template.format("")
        captions.append(caption)
    
    # Add some AI-powered creative captions
    creative_captions = [
        "Making memories that last forever! 📸",
        "Capturing the moment, creating stories! ✨",
        "Life's beautiful moments deserve to be shared! 🌟",
        "Every picture tells a story, what's yours? 📖",
        "Creating waves of inspiration! 🌊"
    ]
    
    captions.extend(creative_captions[:3])
    
    return jsonify({
        'captions': captions,
        'suggested': captions[0] if captions else "Share your moment! 📸",
        'mood': mood,
        'sentiment': analysis['sentiment']
    })

# ///////////////////////////  RECOMENDATION ENGINE  //////////////////////////

#class UserPreference(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
 #   user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  #  category = db.Column(db.String(50))
   # interest_score = db.Column(db.Float, default=0.0)
#    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

#class ContentInteraction(db.Model):
  #  id = db.Column(db.Integer, primary_key=True)
  #  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #content_id = db.Column(db.Integer)
 #   content_type = db.Column(db.String(20))  # 'post', 'reel', 'story'
#    interaction_type = db.Column(db.String(20))  # 'like', 'comment', 'share', 'view'
   # duration = db.Column(db.Integer)  # View duration in seconds
 #   created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@app.route('/api/recommendations/personalized', methods=['GET'])
@token_required
def get_personalized_recommendations(current_user):
    """Get personalized content recommendations"""
    # Get user preferences and interactions
    user_preferences = UserPreference.query.filter_by(user_id=current_user.id).all()
    recent_interactions = ContentInteraction.query.filter_by(
        user_id=current_user.id
    ).order_by(ContentInteraction.created_at.desc()).limit(100).all()
    
    # Analyze user interests
    user_interests = analyze_user_interests(current_user.id, recent_interactions)
    
    # Get recommended content based on interests
    recommended_content = get_recommended_content(current_user.id, user_interests)
    
    return jsonify({
        'recommendations': recommended_content,
        'user_interests': user_interests,
        'reasoning': generate_recommendation_reasoning(user_interests)
    })

def analyze_user_interests(user_id, interactions):
    """Analyze user interests based on interactions"""
    interest_scores = {}
    
    for interaction in interactions:
        # Get content category (you would extract this from content in production)
        category = get_content_category(interaction.content_id, interaction.content_type)
        
        if category not in interest_scores:
            interest_scores[category] = 0
        
        # Weight different interaction types
        weights = {
            'like': 2,
            'comment': 3,
            'share': 4,
            'view': 1
        }
        
        interest_scores[category] += weights.get(interaction.interaction_type, 1)
    
    # Normalize scores
    max_score = max(interest_scores.values()) if interest_scores else 1
    normalized_interests = {
        category: score / max_score 
        for category, score in interest_scores.items()
    }
    
    return dict(sorted(normalized_interests.items(), key=lambda x: x[1], reverse=True))

def get_content_category(content_id, content_type):
    """Get category for content (simplified - implement based on your content taxonomy)"""
    # This is a simplified version - implement proper content categorization
    categories = ['travel', 'food', 'fitness', 'fashion', 'tech', 'art', 'music', 'sports']
    return categories[content_id % len(categories)]

def get_recommended_content(user_id, user_interests, limit=20):
    """Get content recommendations based on user interests"""
    # Get top interests
    top_interests = list(user_interests.keys())[:3]
    
    # Build query based on interests
    recommended_posts = []
    
    for interest in top_interests:
        # In production, you'd have actual content categorization
        # This is a simplified version that gets popular posts
        posts = Post.query.filter(
            Post.user_id != user_id
        ).order_by(
            (Post.likes + Post.comments_count * 2).desc()
        ).limit(limit // len(top_interests) if top_interests else limit).all()
        
        for post in posts:
            user = User.query.get(post.user_id)
            recommended_posts.append({
                'id': post.id,
                'type': 'post',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar,
                    'is_verified': user.is_verified
                },
                'content': post.content,
                'image': post.image,
                'likes': post.likes,
                'comments_count': post.comments_count,
                'created_at': post.created_at.isoformat(),
                'reason': f"Popular in {interest}",
                'relevance_score': user_interests.get(interest, 0.5)
            })
    
    # Sort by relevance score and remove duplicates
    unique_posts = {}
    for post in recommended_posts:
        if post['id'] not in unique_posts:
            unique_posts[post['id']] = post
    
    sorted_posts = sorted(unique_posts.values(), key=lambda x: x['relevance_score'], reverse=True)
    
    return sorted_posts[:limit]

def generate_recommendation_reasoning(user_interests):
    """Generate human-readable reasoning for recommendations"""
    if not user_interests:
        return "Based on popular content in our community"
    
    top_interest = list(user_interests.keys())[0]
    score = user_interests[top_interest]
    
    if score > 0.8:
        return f"Because you love {top_interest} content"
    elif score > 0.5:
        return f"Based on your interest in {top_interest}"
    else:
        return "Discovering new content you might like"

# ****************************  TRENDING AND DISCOVERY  *********************

@app.route('/api/recommendations/trending', methods=['GET'])
@token_required
def get_trending_recommendations(current_user):
    """Get trending content recommendations"""
    # Get posts with high engagement in last 24 hours
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
    
    trending_posts = Post.query.filter(
        Post.created_at >= cutoff_time
    ).order_by(
        ((Post.likes * 1) + (Post.comments_count * 2) + (Post.shares * 3)).desc()
    ).limit(15).all()
    
    trending_data = []
    for post in trending_posts:
        user = User.query.get(post.user_id)
        trending_data.append({
            'id': post.id,
            'type': 'post',
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'content': post.content,
            'image': post.image,
            'engagement_score': (post.likes + post.comments_count * 2 + post.shares * 3),
            'trending_reason': get_trending_reason(post),
            'created_at': post.created_at.isoformat()
        })
    
    return jsonify({
        'trending': trending_data,
        'timeframe': 'last_24_hours'
    })

def get_trending_reason(post):
    """Get reason why content is trending"""
    engagement_score = post.likes + post.comments_count * 2 + post.shares * 3
    
    if engagement_score > 100:
        return "🔥 Viral in your network"
    elif engagement_score > 50:
        return "📈 Rapidly gaining traction"
    elif engagement_score > 20:
        return "🌟 Getting popular"
    else:
        return "✨ Emerging trend"

# ££££££££££€€€€€€€€££€£€££€€££€£€€£££€£€ SIMILAR CONTENT £€£€€£££€€€£€£€£€€€£££€€€££

@app.route('/api/recommendations/similar/<int:content_id>', methods=['GET'])
@token_required
def get_similar_content(current_user, content_id):
    """Get content similar to a specific post"""
    target_post = Post.query.get_or_404(content_id)
    
    # In production, you'd use ML for content similarity
    # This is a simplified version using text similarity
    
    similar_posts = Post.query.filter(
        Post.id != content_id,
        Post.user_id != current_user.id
    ).order_by(Post.created_at.desc()).limit(20).all()
    
    # Simple content similarity (implement proper NLP in production)
    similar_content = []
    for post in similar_posts:
        similarity_score = calculate_text_similarity(target_post.content, post.content)
        
        if similarity_score > 0.1:  # Threshold for similarity
            user = User.query.get(post.user_id)
            similar_content.append({
                'id': post.id,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar
                },
                'content': post.content,
                'image': post.image,
                'similarity_score': similarity_score,
                'reason': "Similar content"
            })
    
    # Sort by similarity score
    similar_content.sort(key=lambda x: x['similarity_score'], reverse=True)
    
    return jsonify({
        'similar_content': similar_content[:10],
        'original_content': {
            'id': target_post.id,
            'content': target_post.content
        }
    })

def calculate_text_similarity(text1, text2):
    """Calculate simple text similarity (implement proper NLP in production)"""
    if not text1 or not text2:
        return 0
    
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    
    if not words1 or not words2:
        return 0
    
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    
    return len(intersection) / len(union) if union else 0

# ==================== VOICE & VIDEO CALL ROUTES ====================

@app.route('/api/calls/start', methods=['POST'])
@token_required
def start_call(current_user):
    """Start a voice or video call"""
    data = request.json
    receiver_id = data.get('receiver_id')
    call_type = data.get('call_type', 'voice')

    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'error': 'User not found'}), 404

    # Create call record
    call = Call(
        caller_id=current_user.id,
        receiver_id=receiver_id,
        call_type=call_type,
        status='ringing',
        started_at=datetime.now(timezone.utc)
    )
    db.session.add(call)
    db.session.commit()

    print(f"📞 Call {call.id} started from {current_user.id} to {receiver_id}")

    # Send call notification via WebSocket
    socketio.emit('incoming_call', {
        'call_id': call.id,
        'caller': {
            'id': current_user.id,
            'username': current_user.username,
            'avatar': current_user.avatar
        },
        'call_type': call_type,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=f'user_{receiver_id}')

    return jsonify({
        'message': f'{call_type.capitalize()} call started',
        'call_id': call.id
    })

@app.route('/api/calls/<call_id>/accept', methods=['POST'])
@token_required
def accept_call(current_user, call_id):
    """Accept an incoming call"""
    call = Call.query.filter_by(call_id=call_id).first_or_404()

    if call.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if call.status != 'calling':
        return jsonify({'error': 'Call is no longer available'}), 400

    # Update call status
    call.status = 'ongoing'
    db.session.commit()

    # Notify caller that call was accepted
    socketio.emit('call_accepted', {
        'call_id': call_id,
        'receiver': {
            'id': current_user.id,
            'username': current_user.username,
            'avatar': current_user.avatar
        }
    }, room=f'user_{call.caller_id}')

    return jsonify({'message': 'Call accepted'})

@app.route('/api/calls/<call_id>/reject', methods=['POST'])
@token_required
def reject_call(current_user, call_id):
    """Reject an incoming call"""
    call = Call.query.filter_by(call_id=call_id).first_or_404()

    if call.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    call.status = 'rejected'
    call.ended_at = datetime.now(timezone.utc)
    db.session.commit()

    # Notify caller that call was rejected
    socketio.emit('call_rejected', {
        'call_id': call_id,
        'receiver_id': current_user.id
    }, room=f'user_{call.caller_id}')

    return jsonify({'message': 'Call rejected'})

@app.route('/api/calls/<call_id>/end', methods=['POST'])
@token_required
def end_call(current_user, call_id):
    """End a call"""
    call = Call.query.filter_by(id=call_id).first()
    
    if not call:
        return jsonify({'error': 'Call not found'}), 404

    if current_user.id not in [call.caller_id, call.receiver_id]:
        return jsonify({'error': 'Unauthorized'}), 403

    call.status = 'ended'
    call.ended_at = datetime.now(timezone.utc)
    
    # Calculate duration safely
    if call.started_at:
        # Ensure both datetimes are timezone-aware
        started_at = call.started_at.replace(tzinfo=timezone.utc) if call.started_at.tzinfo is None else call.started_at
        ended_at = call.ended_at.replace(tzinfo=timezone.utc) if call.ended_at.tzinfo is None else call.ended_at
        duration = int((ended_at - started_at).total_seconds())
        call.duration = duration
    else:
        call.duration = 0

    db.session.commit()

    # Notify other participant
    other_user_id = call.caller_id if current_user.id == call.receiver_id else call.receiver_id
    socketio.emit('call_ended', {
        'call_id': call.id,
        'ended_by': current_user.id,
        'duration': call.duration
    }, room=f'user_{other_user_id}')

    return jsonify({
        'message': 'Call ended',
        'duration': call.duration
    })

@app.route('/api/calls/history', methods=['GET'])
@token_required
def get_call_history(current_user):
    """Get user's call history"""
    calls = Call.query.filter(
        (Call.caller_id == current_user.id) | (Call.receiver_id == current_user.id)
    ).order_by(Call.created_at.desc()).limit(50).all()

    call_history = []
    for call in calls:
        caller = User.query.get(call.caller_id)
        receiver = User.query.get(call.receiver_id)
        
        call_history.append({
            'id': call.id,
            'call_id': call.call_id,
            'caller': {
                'id': caller.id,
                'username': caller.username,
                'avatar': caller.avatar
            },
            'receiver': {
                'id': receiver.id,
                'username': receiver.username,
                'avatar': receiver.avatar
            },
            'call_type': call.call_type,
            'status': call.status,
            'duration': call.duration,
            'started_at': call.started_at.isoformat() if call.started_at else None,
            'ended_at': call.ended_at.isoformat() if call.ended_at else None,
            'is_outgoing': call.caller_id == current_user.id
        })

    return jsonify({'call_history': call_history})

# WebRTC Signaling endpoints
@app.route('/api/calls/<call_id>/offer', methods=['POST'])
@token_required
def send_offer(current_user, call_id):
    """Send WebRTC offer"""
    data = request.json
    offer = data.get('offer')
    
    call = Call.query.filter_by(call_id=call_id).first_or_404()
    other_user_id = call.receiver_id if current_user.id == call.caller_id else call.caller_id

    socketio.emit('webrtc_offer', {
        'call_id': call_id,
        'offer': offer,
        'from_user_id': current_user.id
    }, room=f'user_{other_user_id}')

    return jsonify({'message': 'Offer sent'})

@app.route('/api/calls/<call_id>/answer', methods=['POST'])
@token_required
def send_answer(current_user, call_id):
    """Send WebRTC answer"""
    data = request.json
    answer = data.get('answer')
    
    call = Call.query.filter_by(call_id=call_id).first_or_404()
    other_user_id = call.receiver_id if current_user.id == call.caller_id else call.caller_id

    socketio.emit('webrtc_answer', {
        'call_id': call_id,
        'answer': answer,
        'from_user_id': current_user.id
    }, room=f'user_{other_user_id}')

    return jsonify({'message': 'Answer sent'})

@app.route('/api/calls/<call_id>/ice-candidate', methods=['POST'])
@token_required
def send_ice_candidate(current_user, call_id):
    """Send ICE candidate"""
    data = request.json
    candidate = data.get('candidate')
    
    call = Call.query.filter_by(call_id=call_id).first_or_404()
    other_user_id = call.receiver_id if current_user.id == call.caller_id else call.caller_id

    socketio.emit('webrtc_ice_candidate', {
        'call_id': call_id,
        'candidate': candidate,
        'from_user_id': current_user.id
    }, room=f'user_{other_user_id}')

    return jsonify({'message': 'ICE candidate sent'})

@app.route('/api/calls/info/<call_id>', methods=['GET'])
@token_required
def get_call_info(current_user, call_id):
    """Get call information"""
    call = Call.query.filter_by(id=call_id).first()
    
    if not call:
        return jsonify({'error': 'Call not found'}), 404

    caller = User.query.get(call.caller_id)
    
    return jsonify({
        'call_id': call.id,
        'caller': {
            'id': caller.id,
            'username': caller.username,
            'avatar': caller.avatar
        },
        'call_type': call.call_type,
        'status': call.status
    })

# ==================== NEW FEATURE ROUTES ====================

#=============== AI Service for mood and context detection  =====================
import requests
from PIL import Image
import io
import speech_recognition as sr
#from textblob import TextBlob

class LifeMomentAI:
    def __init__(self):
        self.weather_api_key = os.environ.get('WEATHER_API_KEY')
    
    def analyze_moment(self, image_file=None, audio_file=None, text_content=None, location=None):
        """Comprehensive AI analysis of a life moment"""
        analysis = {
            'mood': 'neutral',
            'mood_confidence': 0.5,
            'weather': None,
            'facial_expression': None,
            'audio_sentiment': None,
            'text_sentiment': None,
            'context_tags': []
        }
        
        # Analyze image if provided
        if image_file:
            analysis.update(self.analyze_image(image_file))
        
        # Analyze audio if provided
        if audio_file:
            analysis.update(self.analyze_audio(audio_file))
        
        # Analyze text if provided
        if text_content:
            analysis.update(self.analyze_text(text_content))
        
        # Get weather data if location provided
        if location:
            analysis.update(self.get_weather_context(location))
        
        # Determine overall mood
        analysis['mood'] = self.determine_overall_mood(analysis)
        
        return analysis
    
    def analyze_image(self, image_file):
        """Analyze image for mood and context"""
        try:
            # Simple computer vision analysis
            image = Image.open(image_file)
            
            # Analyze colors for mood detection
            colors = image.getcolors(maxcolors=10000)
            bright_colors = sum(1 for count, color in colors if sum(color) > 500) if colors else 0
            total_colors = len(colors) if colors else 1
            brightness_ratio = bright_colors / total_colors
            
            mood = 'happy' if brightness_ratio > 0.6 else 'calm' if brightness_ratio > 0.3 else 'moody'
            confidence = min(0.9, brightness_ratio + 0.3)
            
            return {
                'mood': mood,
                'mood_confidence': confidence,
                'facial_expression': 'neutral',  # In production, use face recognition API
                'context_tags': ['photo', 'visual']
            }
        except Exception as e:
            print(f"Image analysis error: {e}")
            return {}
    
    def analyze_audio(self, audio_file):
        """Analyze voice note for sentiment"""
        try:
            r = sr.Recognizer()
            with sr.AudioFile(audio_file) as source:
                audio = r.record(source)
                text = r.recognize_google(audio)
            
            # Simple sentiment analysis
            blob = TextBlob(text)
            sentiment = blob.sentiment.polarity
            
            audio_mood = 'happy' if sentiment > 0.1 else 'sad' if sentiment < -0.1 else 'neutral'
            
            return {
                'audio_sentiment': audio_mood,
                'context_tags': ['voice_note', 'audio'],
                'transcribed_text': text
            }
        except Exception as e:
            print(f"Audio analysis error: {e}")
            return {}
    
    def analyze_text(self, text_content):
        """Analyze text content for sentiment"""
        try:
            blob = TextBlob(text_content)
            sentiment = blob.sentiment
            
            text_mood = 'happy' if sentiment.polarity > 0.3 else \
                       'excited' if sentiment.polarity > 0.1 else \
                       'calm' if sentiment.polarity > -0.1 else \
                       'thoughtful' if sentiment.polarity > -0.3 else 'sad'
            
            return {
                'text_sentiment': text_mood,
                'mood_confidence': abs(sentiment.polarity) + 0.2,
                'context_tags': ['text', 'written']
            }
        except Exception as e:
            print(f"Text analysis error: {e}")
            return {}
    
    def get_weather_context(self, location):
        """Get weather context for location"""
        try:
            if not self.weather_api_key:
                return {'weather': 'unknown'}
            
            lat, lng = location
            url = f"http://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lng}&appid={self.weather_api_key}"
            response = requests.get(url)
            data = response.json()
            
            weather = data.get('weather', [{}])[0].get('main', 'Clear').lower()
            temp = data.get('main', {}).get('temp', 293) - 273.15  # Convert to Celsius
            
            return {
                'weather': weather,
                'temperature': round(temp, 1),
                'context_tags': [weather, f"{round(temp)}°C"]
            }
        except Exception:
            return {'weather': 'unknown'}
    
    def determine_overall_mood(self, analysis):
        """Determine overall mood from multiple analysis sources"""
        moods = []
        confidences = []
        
        if analysis.get('mood'):
            moods.append(analysis['mood'])
            confidences.append(analysis.get('mood_confidence', 0.5))
        
        if analysis.get('audio_sentiment'):
            moods.append(analysis['audio_sentiment'])
            confidences.append(0.7)
        
        if analysis.get('text_sentiment'):
            moods.append(analysis['text_sentiment'])
            confidences.append(0.8)
        
        if not moods:
            return 'neutral'
        
        # Weighted mood selection
        mood_weights = {}
        for mood, confidence in zip(moods, confidences):
            mood_weights[mood] = mood_weights.get(mood, 0) + confidence
        
        return max(mood_weights.items(), key=lambda x: x[1])[0]

life_moment_ai = LifeMomentAI()

# ==================== LIFE MOMENTS FEATURES ====================

@app.route('/api/moments', methods=['POST'])
@token_required
def create_life_moment(current_user):
    """Create a life moment with AI context detection"""
    try:
        # Handle file uploads
        image_file = request.files.get('media')
        audio_file = request.files.get('voice_note')
        text_content = request.form.get('content')
        latitude = request.form.get('latitude', type=float)
        longitude = request.form.get('longitude', type=float)
        location_name = request.form.get('location_name')
        
        # Save media files
        media_url = None
        voice_note_url = None
        
        if image_file:
            filename = f"moment_{current_user.id}_{int(datetime.now().timestamp())}.jpg"
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_url = f"/uploads/{filename}"
        
        if audio_file:
            filename = f"voice_{current_user.id}_{int(datetime.now().timestamp())}.wav"
            audio_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            voice_note_url = f"/uploads/{filename}"
        
        # AI Analysis
        location = (latitude, longitude) if latitude and longitude else None
        ai_analysis = life_moment_ai.analyze_moment(
            image_file=image_file if image_file else None,
            audio_file=audio_file if audio_file else None,
            text_content=text_content,
            location=location
        )
        
        # Create life moment
        moment = LifeMoment(
            user_id=current_user.id,
            content=text_content,
            media_url=media_url,
            voice_note_url=voice_note_url,
            media_type='photo_360' if '360' in request.form.get('media_type', '') else 'image',
            mood=ai_analysis['mood'],
            mood_confidence=ai_analysis['mood_confidence'],
            weather=ai_analysis.get('weather'),
            location_name=location_name,
            latitude=latitude,
            longitude=longitude,
            temperature=ai_analysis.get('temperature'),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        
        db.session.add(moment)
        db.session.flush()  # Get moment ID
        
        # Save detailed analysis
        mood_analysis = MoodAnalysis(
            user_id=current_user.id,
            moment_id=moment.id,
            detected_mood=ai_analysis['mood'],
            confidence=ai_analysis['mood_confidence'],
            facial_expression=ai_analysis.get('facial_expression'),
            audio_sentiment=ai_analysis.get('audio_sentiment'),
            text_sentiment=ai_analysis.get('text_sentiment'),
            analysis_data=json.dumps(ai_analysis)
        )
        db.session.add(mood_analysis)
        db.session.commit()
        
        # Notify friends
        socketio.emit('new_life_moment', {
            'moment_id': moment.id,
            'user_id': current_user.id,
            'username': current_user.username,
            'mood': moment.mood,
            'preview_content': text_content[:100] if text_content else "Shared a moment",
            'created_at': moment.created_at.isoformat()
        }, broadcast=True)
        
        return jsonify({
            'message': 'Life moment created',
            'moment_id': moment.id,
            'ai_analysis': ai_analysis
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/moments/feed', methods=['GET'])
@token_required
def get_moments_feed(current_user):
    """Get life moments feed from friends"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get moments from followed users
    following_ids = [f.following_id for f in current_user.following]
    following_ids.append(current_user.id)  # Include own moments
    
    moments = LifeMoment.query.filter(
        LifeMoment.user_id.in_(following_ids),
        LifeMoment.expires_at > datetime.now(timezone.utc),
        LifeMoment.is_public == True
    ).order_by(LifeMoment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    moments_data = []
    for moment in moments.items:
        user = User.query.get(moment.user_id)
        
        # Get reaction counts
        video_reactions = MomentReaction.query.filter_by(
            moment_id=moment.id, 
            reaction_type='video_response'
        ).count()
        
        emoji_reactions = MomentReaction.query.filter_by(
            moment_id=moment.id
        ).filter(MomentReaction.reaction_type != 'video_response').count()
        
        # Check if current user reacted
        user_reacted = MomentReaction.query.filter_by(
            moment_id=moment.id,
            user_id=current_user.id
        ).first() is not None
        
        moments_data.append({
            'id': moment.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'content': moment.content,
            'media_url': moment.media_url,
            'voice_note_url': moment.voice_note_url,
            'media_type': moment.media_type,
            'mood': moment.mood,
            'mood_confidence': moment.mood_confidence,
            'weather': moment.weather,
            'location_name': moment.location_name,
            'temperature': moment.temperature,
            'video_reactions_count': video_reactions,
            'emoji_reactions_count': emoji_reactions,
            'user_reacted': user_reacted,
            'created_at': moment.created_at.isoformat(),
            'expires_in': int((moment.expires_at - datetime.now(timezone.utc)).total_seconds() / 3600)
        })
    
    return jsonify({
        'moments': moments_data,
        'total_pages': moments.pages,
        'current_page': page
    })

@app.route('/api/moments/<int:moment_id>/react', methods=['POST'])
@token_required
def react_to_moment(current_user, moment_id):
    """React to a life moment with video or emoji"""
    moment = LifeMoment.query.get_or_404(moment_id)
    data = request.json
    reaction_type = data.get('reaction_type', 'emoji')
    
    # Check if user already reacted
    existing_reaction = MomentReaction.query.filter_by(
        moment_id=moment_id,
        user_id=current_user.id
    ).first()
    
    if existing_reaction:
        return jsonify({'error': 'Already reacted to this moment'}), 400
    
    if reaction_type == 'video_response':
        # Handle video reaction upload
        video_file = request.files.get('video')
        if not video_file:
            return jsonify({'error': 'Video file required'}), 400
        
        filename = f"reaction_{current_user.id}_{int(datetime.now().timestamp())}.mp4"
        video_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        video_url = f"/uploads/{filename}"
        
        reaction = MomentReaction(
            moment_id=moment_id,
            user_id=current_user.id,
            reaction_type='video_response',
            video_url=video_url,
            duration=data.get('duration', 0)
        )
    else:
        # Emoji reaction
        reaction = MomentReaction(
            moment_id=moment_id,
            user_id=current_user.id,
            reaction_type='emoji',
            emoji=data.get('emoji', '❤️')
        )
    
    db.session.add(reaction)
    db.session.commit()
    
    # Notify moment owner
    if moment.user_id != current_user.id:
        socketio.emit('moment_reaction', {
            'moment_id': moment_id,
            'reactor_id': current_user.id,
            'reactor_username': current_user.username,
            'reaction_type': reaction_type,
            'emoji': data.get('emoji'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f'user_{moment.user_id}')
    
    return jsonify({'message': 'Reaction added', 'reaction_id': reaction.id})

@app.route('/api/moments/<int:moment_id>/reactions', methods=['GET'])
@token_required
def get_moment_reactions(current_user, moment_id):
    """Get reactions for a specific moment"""
    reactions = MomentReaction.query.filter_by(moment_id=moment_id).order_by(
        MomentReaction.created_at.desc()
    ).all()
    
    reactions_data = []
    for reaction in reactions:
        user = User.query.get(reaction.user_id)
        reaction_data = {
            'id': reaction.id,
            'user': {
                'id': user.id,
                'username': user.username,
                'avatar': user.avatar
            },
            'reaction_type': reaction.reaction_type,
            'emoji': reaction.emoji,
            'duration': reaction.duration,
            'created_at': reaction.created_at.isoformat()
        }
        
        if reaction.reaction_type == 'video_response':
            reaction_data['video_url'] = reaction.video_url
        
        reactions_data.append(reaction_data)
    
    return jsonify({'reactions': reactions_data})

@app.route('/api/moments/mood-insights', methods=['GET'])
@token_required
def get_mood_insights(current_user):
    """Get AI-powered mood insights over time"""
    # Get last 30 days of mood data
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    
    mood_data = MoodAnalysis.query.filter(
        MoodAnalysis.user_id == current_user.id,
        MoodAnalysis.created_at >= thirty_days_ago
    ).order_by(MoodAnalysis.created_at.asc()).all()
    
    # Mood trends
    mood_counts = {}
    mood_timeline = []
    
    for analysis in mood_data:
        mood = analysis.detected_mood
        mood_counts[mood] = mood_counts.get(mood, 0) + 1
        mood_timeline.append({
            'date': analysis.created_at.date().isoformat(),
            'mood': mood,
            'confidence': analysis.confidence
        })
    
    # Most common contexts
    context_analysis = LifeMoment.query.filter(
        LifeMoment.user_id == current_user.id,
        LifeMoment.created_at >= thirty_days_ago
    ).all()
    
    location_moods = {}
    weather_moods = {}
    
    for moment in context_analysis:
        if moment.location_name:
            location_moods[moment.location_name] = location_moods.get(moment.location_name, [])
            location_moods[moment.location_name].append(moment.mood)
        
        if moment.weather:
            weather_moods[moment.weather] = weather_moods.get(moment.weather, [])
            weather_moods[moment.weather].append(moment.mood)
    
    # Calculate insights
    dominant_mood = max(mood_counts.items(), key=lambda x: x[1])[0] if mood_counts else 'neutral'
    
    insights = {
        'dominant_mood': dominant_mood,
        'mood_distribution': mood_counts,
        'mood_timeline': mood_timeline[-7:],  # Last 7 days
        'location_insights': {
            loc: max(set(moods), key=moods.count) if moods else 'neutral'
            for loc, moods in location_moods.items()
        },
        'weather_insights': {
            weather: max(set(moods), key=moods.count) if moods else 'neutral'
            for weather, moods in weather_moods.items()
        },
        'total_moments': len(mood_data)
    }
    
    return jsonify(insights)

# ==================== WEBSOCKET EVENTS ====================

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    if not GOOGLE_AUTH_AVAILABLE:
        return jsonify({
            'error': 'Google authentication temporarily disabled for deployment',
            'message': 'Use regular email registration for now'
        }), 501
    
    try:
        data = request.get_json()
        token = data.get('token')
        
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), 
            'your-google-client-id'  # Replace with your actual client ID
        )
        
        # Rest of your Google auth logic...
        return jsonify({'message': 'Google auth successful'})
        
    except ValueError:
        return jsonify({'error': 'Invalid token'}), 400

#@socketio.on('connect')
##def handle_connect():
  #  print('Client connected')
 #   emit('connection_response', {'status': 'connected'})

##@socketio.on('disconnect')
#def handle_disconnect():
#    print('Client disconnected')

#@socketio.on('join')
#def handle_join(data):
 #   room = f"user_{data['user_id']}"
  #  join_room(room)
   # emit('joined', {'room': room})

#@s#ocketio.on('leave')
#def handle_leave(data):
  #  room = f"user_{data['user_id']}"
 #   leave_room(room)
 #   emit('left', {'room': room})
#
#@socketio.on('user_online')
#def handle_user_online(data):
#    user_id = data.get('user_id')
#    if user_id:
 #       user = User.query.get(user_id)
    #    if user:
   #         user.is_online = True
  #          user.last_seen = datetime.now(timezone.utc)
 #           db.session.commit()
  #          emit('user_status', {'user_id': user_id, 'online': True})
#
#@socketio.on('typing')
#def handle_typing(data):
#    room = data.get('room')
  #  username = data.get('username')
 #   emit('user_typing', {'username': username}, room=room, broadcast=True)

#@socketio.on('send_message')
#def handle_send_message(data):
#    sender_id = data.get('sender_id')
 #   receiver_id = data.get('receiver_id')
 #   content = data.get('content')

   # message = Message(
  #      sender_id=sender_id,
  #      receiver_id=receiver_id,
 #       content=content
#    )
 # #  #db.session.add(message)
  #  db.session.commit()
#
  #  emit('receive_message', {
#   # #    'id': message.id,
   #     'sender_id': sender_id,
 ##       'content': content,
  #      'timestamp': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
    #}, room=f'user_{receiver_id}')
##
# Add to your existing socketio events
@socketio.on('join_stream')
def handle_join_stream(data):
    stream_id = data.get('stream_id')
    join_room(f'stream_{stream_id}')
    emit('joined_stream', {'stream_id': stream_id})

@socketio.on('leave_stream')
def handle_leave_stream(data):
    stream_id = data.get('stream_id')
    leave_room(f'stream_{stream_id}')
    emit('left_stream', {'stream_id': stream_id})

@socketio.on('stream_heartbeat')
def handle_stream_heartbeat(data):
    """Streamer sends heartbeat to keep stream active"""
    stream_id = data.get('stream_id')
    # Update last activity timestamp for the stream
    # This helps detect if streamer is still broadcasting
    pass

# Add to your existing socketio events
#@socketio.on('join_call')
#def handle_join_call(data):
  #  """User joins a call room"""
 #   call_id = data.get('call_id')
   # user_id = data.get('user_id')
    
#    if call_id and user_id:
  #      join_room(f'call_{call_id}')
 #       emit('user_joined_call', {'user_id': user_id}, room=f'call_{call_id}')

#@socketio.on('leave_call')
#def handle_leave_call(data):
  #  """User leaves a call room"""
 #   call_id = data.get('call_id')
   # user_id = data.get('user_id')
#    
 #   if call_id and user_id:
  #      leave_room(f'call_{call_id}')
   #     emit('user_left_call', {'user_id': user_id}, room=f'call_{call_id}')

#@socketio.on('webrtc_offer')
#def handle_webrtc_offer(data):
#    """Handle WebRTC offer"""
  #  call_id = data.get('call_id')
 #   offer = data.get('offer')
   # user_id = data.get('user_id')
    
 #   emit('webrtc_offer', {
#        'offer': offer,
   #     'user_id': user_id
  #  }, room=f'call_{call_id}', include_self=False)

#@socketio.on('webrtc_answer')
#def handle_webrtc_answer(data):
#    """Handle WebRTC answer"""
 #   call_id = data.get('call_id')
  #  answer = data.get('answer')
 #   user_id = data.get('user_id')
    
#    emit('webrtc_answer', {
  #      'answer': answer,
    #    'user_id': user_id
   # }, room=f'call_{call_id}', include_self=False)

#@socketio.on('webrtc_ice_candidate')
#def handle_webrtc_ice_candidate(data):
##    """Handle WebRTC ICE candidate"""
  #  call_id = data.get('call_id')
  #  candidate = data.get('candidate')
   # user_id = data.get('user_id')
 #   
#    emit('webrtc_ice_candidate', {
#        'candidate': candidate,
 #       'user_id': user_id
  #  }, room=f'call_{call_id}', include_self=False)

@socketio.on('call_audio_toggle')
def handle_call_audio_toggle(data):
    """Handle audio mute/unmute"""
    call_id = data.get('call_id')
    user_id = data.get('user_id')
    audio_enabled = data.get('audio_enabled')
    
    emit('user_audio_toggled', {
        'user_id': user_id,
        'audio_enabled': audio_enabled
    }, room=f'call_{call_id}', include_self=False)

@socketio.on('call_video_toggle')
def handle_call_video_toggle(data):
    """Handle video on/off"""
    call_id = data.get('call_id')
    user_id = data.get('user_id')
    video_enabled = data.get('video_enabled')
    
    emit('user_video_toggled', {
        'user_id': user_id,
        'video_enabled': video_enabled
    }, room=f'call_{call_id}', include_self=False)

#gjfjfgjgjhjhhhhhjjjgfifiifigkhkhkfifofifoghohhooh

# ==================== WEB SOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    if user_id:
        room = f"user_{user_id}"
        join_room(room)
        print(f'User {user_id} joined room {room}')
        emit('joined_room', {'room': room})

@socketio.on('leave')
def handle_leave(data):
    user_id = data.get('user_id')
    if user_id:
        room = f"user_{user_id}"
        leave_room(room)
        emit('left_room', {'room': room})

@socketio.on('user_online')
def handle_user_online(data):
    user_id = data.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.is_online = True
            user.last_seen = datetime.now(timezone.utc)
            db.session.commit()
            print(f'User {user_id} is online')
            emit('user_status', {
                'user_id': user_id, 
                'online': True,
                'username': user.username
            }, broadcast=True)

@socketio.on('user_offline')
def handle_user_offline(data):
    user_id = data.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.is_online = False
            user.last_seen = datetime.now(timezone.utc)
            db.session.commit()
            print(f'User {user_id} is offline')
            emit('user_status', {
                'user_id': user_id, 
                'online': False,
                'username': user.username
            }, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    
    if sender_id and receiver_id:
        print(f'User {sender_id} typing to {receiver_id}')
        emit('user_typing', {
            'sender_id': sender_id,
            'receiver_id': receiver_id
        }, room=f'user_{receiver_id}')

@socketio.on('stop_typing')
def handle_stop_typing(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    
    if sender_id and receiver_id:
        print(f'User {sender_id} stopped typing to {receiver_id}')
        emit('user_stop_typing', {
            'sender_id': sender_id,
            'receiver_id': receiver_id
        }, room=f'user_{receiver_id}')

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')

    if not all([sender_id, receiver_id, content]):
        return

    try:
        # Create message in database
        message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content
        )
        db.session.add(message)
        db.session.commit()

        # Get sender info
        sender = User.query.get(sender_id)
        
        # Emit to receiver
        emit('new_message', {
            'id': message.id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'content': content,
            'sender_username': sender.username,
            'sender_avatar': sender.avatar,
            'timestamp': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': False
        }, room=f'user_{receiver_id}')

        # Also emit to sender for real-time update
        emit('new_message', {
            'id': message.id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'content': content,
            'sender_username': sender.username,
            'sender_avatar': sender.avatar,
            'timestamp': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': False
        }, room=f'user_{sender_id}')

        print(f'Message sent from {sender_id} to {receiver_id}: {content}')

    except Exception as e:
        print(f"Error sending message: {e}")

# Call-related WebSocket events
@socketio.on('join_call')
def handle_join_call(data):
    call_id = data.get('call_id')
    user_id = data.get('user_id')
    
    if call_id and user_id:
        room = f'call_{call_id}'
        join_room(room)
        print(f'User {user_id} joined call room {room}')
        emit('user_joined_call', {
            'user_id': user_id,
            'call_id': call_id
        }, room=room)

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    call_id = data.get('call_id')
    offer = data.get('offer')
    user_id = data.get('user_id')
    
    print(f'WebRTC offer from user {user_id} in call {call_id}')
    emit('webrtc_offer', {
        'offer': offer,
        'user_id': user_id
    }, room=f'call_{call_id}', include_self=False)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    call_id = data.get('call_id')
    answer = data.get('answer')
    user_id = data.get('user_id')
    
    print(f'WebRTC answer from user {user_id} in call {call_id}')
    emit('webrtc_answer', {
        'answer': answer,
        'user_id': user_id
    }, room=f'call_{call_id}', include_self=False)

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    call_id = data.get('call_id')
    candidate = data.get('candidate')
    user_id = data.get('user_id')
    
    emit('webrtc_ice_candidate', {
        'candidate': candidate,
        'user_id': user_id
    }, room=f'call_{call_id}', include_self=False)

# ==================== PRIVACY & GHOST MODE ROUTES ====================

@app.route('/api/privacy/settings', methods=['GET'])
@token_required
def get_privacy_settings(current_user):
    """Get user privacy settings"""
    settings = PrivacySettings.query.filter_by(user_id=current_user.id).first()
    
    if not settings:
        # Create default settings
        settings = PrivacySettings(user_id=current_user.id)
        db.session.add(settings)
        db.session.commit()
    
    return jsonify({
        'ghost_mode': settings.ghost_mode,
        'last_seen_visibility': settings.last_seen_visibility,
        'read_receipts': settings.read_receipts,
        'profile_visibility': settings.profile_visibility
    })

@app.route('/api/privacy/settings', methods=['PUT'])
@token_required
def update_privacy_settings(current_user):
    """Update privacy settings"""
    data = request.json
    
    settings = PrivacySettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = PrivacySettings(user_id=current_user.id)
        db.session.add(settings)
    
    if 'ghost_mode' in data:
        settings.ghost_mode = data['ghost_mode']
        if data['ghost_mode']:
            # User went ghost - update last seen
            current_user.last_seen = datetime.now(timezone.utc)
    
    if 'last_seen_visibility' in data:
        settings.last_seen_visibility = data['last_seen_visibility']
    
    if 'read_receipts' in data:
        settings.read_receipts = data['read_receipts']
    
    if 'profile_visibility' in data:
        settings.profile_visibility = data['profile_visibility']
    
    db.session.commit()
    
    # Notify connections about status change
    socketio.emit('user_privacy_updated', {
        'user_id': current_user.id,
        'ghost_mode': settings.ghost_mode
    }, broadcast=True)
    
    return jsonify({'message': 'Privacy settings updated'})

@app.route('/api/privacy/last-seen/<int:user_id>', methods=['GET'])
@token_required
def get_last_seen(current_user, user_id):
    """Get user's last seen with privacy respect"""
    target_user = User.query.get_or_404(user_id)
    target_settings = PrivacySettings.query.filter_by(user_id=user_id).first()
    
    if not target_settings:
        return jsonify({'last_seen': target_user.last_seen.isoformat()})
    
    # Check privacy settings
    if target_settings.ghost_mode:
        return jsonify({'last_seen': None, 'ghost_mode': True})
    
    if target_settings.last_seen_visibility == 'nobody':
        return jsonify({'last_seen': None})
    
    if target_settings.last_seen_visibility == 'contacts':
        # Check if users follow each other
        is_contact = Follow.query.filter_by(
            follower_id=current_user.id, 
            following_id=user_id
        ).first() is not None
        
        if not is_contact:
            return jsonify({'last_seen': None})
    
    return jsonify({
        'last_seen': target_user.last_seen.isoformat(),
        'is_online': target_user.is_online
    })

@app.route('/api/analytics/views', methods=['GET'])
@token_required
def get_view_analytics(current_user):
    """Get who viewed your content"""
    # Get profile views
    profile_views = UserViewTracking.query.filter_by(
        viewed_user_id=current_user.id,
        content_type='profile'
    ).order_by(UserViewTracking.created_at.desc()).limit(50).all()
    
    views_data = []
    for view in profile_views:
        viewer = User.query.get(view.viewer_id)
        views_data.append({
            'viewer': {
                'id': viewer.id,
                'username': viewer.username,
                'avatar': viewer.avatar
            },
            'content_type': view.content_type,
            'view_duration': view.view_duration,
            'timestamp': view.created_at.isoformat()
        })
    
    # Get algorithm transparency data
    algorithm_data = AlgorithmTransparency.query.filter_by(
        user_id=current_user.id
    ).order_by(AlgorithmTransparency.created_at.desc()).limit(20).all()
    
    algorithm_insights = []
    for insight in algorithm_data:
        algorithm_insights.append({
            'content_type': insight.content_type,
            'engagement_score': insight.engagement_score,
            'visibility_score': insight.visibility_score,
            'factors': json.loads(insight.algorithm_factors) if insight.algorithm_factors else {},
            'timestamp': insight.created_at.isoformat()
        })
    
    return jsonify({
        'profile_views': views_data,
        'algorithm_insights': algorithm_insights
    })

@app.route('/api/analytics/track-view', methods=['POST'])
@token_required
def track_view(current_user):
    """Track when user views someone's content"""
    data = request.json
    
    view_tracking = UserViewTracking(
        viewer_id=current_user.id,
        viewed_user_id=data['viewed_user_id'],
        content_type=data.get('content_type', 'profile'),
        content_id=data.get('content_id'),
        view_duration=data.get('view_duration', 0)
    )
    
    db.session.add(view_tracking)
    
    # Update algorithm transparency
    if data.get('content_id'):
        update_algorithm_transparency(data['viewed_user_id'], data['content_id'], data['content_type'])
    
    db.session.commit()
    
    return jsonify({'message': 'View tracked'})

def update_algorithm_transparency(user_id, content_id, content_type):
    """Update algorithm transparency metrics"""
    # Calculate engagement score (simplified)
    if content_type == 'post':
        post = Post.query.get(content_id)
        if post:
            engagement_score = (post.likes * 1 + post.comments_count * 2 + post.shares * 3) / 10
            visibility_score = min(100, engagement_score * 10)
            
            factors = {
                'likes': post.likes,
                'comments': post.comments_count,
                'shares': post.shares,
                'recency': (datetime.now(timezone.utc) - post.created_at).total_seconds() / 3600
            }
            
            transparency = AlgorithmTransparency(
                user_id=user_id,
                content_id=content_id,
                content_type=content_type,
                engagement_score=engagement_score,
                visibility_score=visibility_score,
                algorithm_factors=json.dumps(factors)
            )
            
            db.session.add(transparency)

# &&&&&&&&&&&&&&&&&&&&&&&&&&___________________$$$$$$$$$$$$&$$$$$$$$$$$$&&

# FIXED Encryption utilities
from cryptography.fernet import Fernet
import base64
import os

   # In your app.py, find the EncryptionService class and replace it with:

class EncryptionService:
    def __init__(self):
        self.key = os.environ.get('ENCRYPTION_KEY')
        if self.key:
            # FIXED: Proper encoding with correct parentheses
            key_bytes = base64.urlsafe_b64encode(self.key.encode()[:32].ljust(32, b'\0'))
            self.cipher = Fernet(key_bytes)
        else:
            self.cipher = None
    
    def encrypt_message(self, message):
        if not self.cipher:
            return message  # Fallback to plaintext if no key
        try:
            return self.cipher.encrypt(message.encode()).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return message
    
    def decrypt_message(self, encrypted_message):
        if not self.cipher:
            return encrypted_message
        try:
            return self.cipher.decrypt(encrypted_message.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "[Unable to decrypt message]"

encryption_service = EncryptionService()

@app.route('/api/messages/encrypted/send', methods=['POST'])
@token_required
def send_encrypted_message(current_user):
    """Send encrypted message"""
    data = request.json
    content = data.get('content')
    receiver_id = data.get('receiver_id')
    
    # Encrypt message
    encrypted_content = encryption_service.encrypt_message(content)
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=encrypted_content,
        is_encrypted=True
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Send via WebSocket (encrypted)
    socketio.emit('new_encrypted_message', {
        'id': message.id,
        'sender_id': current_user.id,
        'receiver_id': receiver_id,
        'encrypted_content': encrypted_content,
        'is_encrypted': True,
        'timestamp': message.created_at.isoformat()
    }, room=f'user_{receiver_id}')
    
    return jsonify({'message': 'Encrypted message sent'})

@app.route('/api/messages/encrypted/decrypt', methods=['POST'])
@token_required
def decrypt_message(current_user):
    """Decrypt encrypted message"""
    data = request.json
    encrypted_content = data.get('encrypted_content')
    message_id = data.get('message_id')
    
    try:
        decrypted_content = encryption_service.decrypt_message(encrypted_content)
        
        return jsonify({
            'decrypted_content': decrypted_content,
            'message_id': message_id
        })
    except Exception as e:
        return jsonify({'error': 'Decryption failed'}), 400


# ==================== AR & REALITY FEATURES ====================

@app.route('/api/ar/filters', methods=['GET'])
def get_ar_filters():
    """Get available AR filters"""
    filters = ARFilter.query.filter_by(is_active=True).all()
    
    filters_data = []
    for filter_obj in filters:
        filters_data.append({
            'id': filter_obj.id,
            'name': filter_obj.name,
            'category': filter_obj.category,
            'trigger_type': filter_obj.trigger_type,
            'preview_emoji': filter_obj.preview_emoji,
            'filter_data': json.loads(filter_obj.filter_data) if filter_obj.filter_data else {}
        })
    
    return jsonify({'filters': filters_data})

@app.route('/api/ar/reality-posts', methods=['GET'])
@token_required
def get_reality_posts(current_user):
    """Get AR reality posts near user's location"""
    latitude = request.args.get('lat', type=float)
    longitude = request.args.get('lng', type=float)
    radius = request.args.get('radius', 1000, type=float)  # meters
    
    if not all([latitude, longitude]):
        return jsonify({'error': 'Location required'}), 400
    
    # Get posts within radius (simplified calculation)
    nearby_posts = ARRealityPost.query.filter(
        ARRealityPost.expires_at > datetime.now(timezone.utc)
    ).all()
    
    # Filter by distance (in production, use PostGIS or similar)
    posts_data = []
    for post in nearby_posts:
        if post.latitude and post.longitude:
            distance = calculate_distance(latitude, longitude, post.latitude, post.longitude)
            if distance <= radius:
                user = User.query.get(post.user_id)
                ar_filter = ARFilter.query.get(post.ar_filter_id)
                
                posts_data.append({
                    'id': post.id,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'avatar': user.avatar
                    },
                    'content': post.content,
                    'media_url': post.media_url,
                    'latitude': post.latitude,
                    'longitude': post.longitude,
                    'distance': distance,
                    'ar_filter': {
                        'name': ar_filter.name if ar_filter else None,
                        'preview_emoji': ar_filter.preview_emoji if ar_filter else None
                    } if ar_filter else None,
                    'created_at': post.created_at.isoformat()
                })
    
    return jsonify({'posts': posts_data})

@app.route('/api/ar/reality-posts', methods=['POST'])
@token_required
def create_reality_post(current_user):
    """Create AR reality post"""
    data = request.json
    
    post = ARRealityPost(
        user_id=current_user.id,
        content=data.get('content'),
        media_url=data.get('media_url'),
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        ar_filter_id=data.get('ar_filter_id'),
        visibility_radius=data.get('visibility_radius', 100),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
    )
    
    db.session.add(post)
    
    # Update geo hotspots
    update_geo_hotspots(data.get('latitude'), data.get('longitude'))
    
    db.session.commit()
    
    return jsonify({
        'message': 'AR reality post created',
        'post_id': post.id
    })

@app.route('/api/ar/hotspots', methods=['GET'])
@token_required
def get_geo_hotspots(current_user):
    """Get nearby geo hotspots"""
    latitude = request.args.get('lat', type=float)
    longitude = request.args.get('lng', type=float)
    radius = request.args.get('radius', 5000, type=float)  # meters
    
    hotspots = GeoHotspot.query.all()
    
    hotspots_data = []
    for hotspot in hotspots:
        if latitude and longitude:
            distance = calculate_distance(latitude, longitude, hotspot.latitude, hotspot.longitude)
            if distance <= radius:
                hotspots_data.append({
                    'id': hotspot.id,
                    'name': hotspot.name,
                    'vibe_type': hotspot.vibe_type,
                    'intensity': hotspot.intensity,
                    'post_count': hotspot.post_count,
                    'latitude': hotspot.latitude,
                    'longitude': hotspot.longitude,
                    'distance': distance
                })
    
    return jsonify({'hotspots': hotspots_data})

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in meters"""
    # Simplified calculation - in production use Haversine formula
    return abs(lat1 - lat2) * 111000 + abs(lon1 - lon2) * 111000  # Approximate

def update_geo_hotspots(latitude, longitude):
    """Update or create geo hotspot"""
    if not latitude or not longitude:
        return
    
    # Find nearby hotspot or create new
    hotspot = GeoHotspot.query.filter(
        GeoHotspot.latitude.between(latitude-0.001, latitude+0.001),
        GeoHotspot.longitude.between(longitude-0.001, longitude+0.001)
    ).first()
    
    if hotspot:
        hotspot.post_count += 1
        hotspot.intensity = min(1.0, hotspot.intensity + 0.1)
        hotspot.last_updated = datetime.now(timezone.utc)
    else:
        hotspot = GeoHotspot(
            latitude=latitude,
            longitude=longitude,
            name=f"Spot {random.randint(1000, 9999)}",
            vibe_type=random.choice(['chill', 'creative', 'social']),
            intensity=0.1,
            post_count=1
        )
        db.session.add(hotspot)

# ==================== CUSTOM PROFILE LAYOUT ====================

@app.route('/api/profile/widgets', methods=['GET'])
@token_required
def get_profile_widgets(current_user):
    """Get user's profile widgets"""
    widgets = ProfileWidget.query.filter_by(user_id=current_user.id).order_by(ProfileWidget.position_y).all()
    
    widgets_data = []
    for widget in widgets:
        widget_info = {
            'id': widget.id,
            'type': widget.widget_type,
            'position': {'x': widget.position_x, 'y': widget.position_y},
            'size': {'width': widget.width, 'height': widget.height},
            'is_visible': widget.is_visible,
            'data': json.loads(widget.widget_data) if widget.widget_data else {}
        }
        
        # Add live data based on widget type
        if widget.widget_type == 'now_playing':
            now_playing = NowPlaying.query.filter_by(user_id=current_user.id).first()
            if now_playing:
                widget_info['live_data'] = {
                    'song_title': now_playing.song_title,
                    'artist': now_playing.artist,
                    'album_art': now_playing.album_art,
                    'is_playing': now_playing.is_playing
                }
        
        elif widget.widget_type == 'mood':
            current_mood = UserMood.query.filter_by(user_id=current_user.id).order_by(UserMood.created_at.desc()).first()
            if current_mood:
                widget_info['live_data'] = {
                    'mood': current_mood.mood,
                    'emoji': current_mood.emoji,
                    'intensity': current_mood.intensity
                }
        
        elif widget.widget_type == 'supporters':
            # Get top supporters (users who interact most)
            top_likers = db.session.query(
                User, db.func.count(Like.id).label('like_count')
            ).join(Like, Like.user_id == User.id).join(
                Post, Post.id == Like.post_id
            ).filter(
                Post.user_id == current_user.id
            ).group_by(User.id).order_by(db.desc('like_count')).limit(5).all()
            
            widget_info['live_data'] = {
                'supporters': [
                    {
                        'id': user.id,
                        'username': user.username,
                        'avatar': user.avatar,
                        'interaction_count': like_count
                    }
                    for user, like_count in top_likers
                ]
            }
        
        widgets_data.append(widget_info)
    
    return jsonify({'widgets': widgets_data})

@app.route('/api/profile/widgets', methods=['POST'])
@token_required
def create_profile_widget(current_user):
    """Create or update profile widget"""
    data = request.json
    
    widget = ProfileWidget.query.filter_by(
        user_id=current_user.id,
        widget_type=data['type']
    ).first()
    
    if widget:
        # Update existing widget
        widget.position_x = data.get('position', {}).get('x', widget.position_x)
        widget.position_y = data.get('position', {}).get('y', widget.position_y)
        widget.width = data.get('size', {}).get('width', widget.width)
        widget.height = data.get('size', {}).get('height', widget.height)
        widget.is_visible = data.get('is_visible', widget.is_visible)
        widget.widget_data = json.dumps(data.get('data', {}))
    else:
        # Create new widget
        widget = ProfileWidget(
            user_id=current_user.id,
            widget_type=data['type'],
            position_x=data.get('position', {}).get('x', 0),
            position_y=data.get('position', {}).get('y', 0),
            width=data.get('size', {}).get('width', 300),
            height=data.get('size', {}).get('height', 200),
            is_visible=data.get('is_visible', True),
            widget_data=json.dumps(data.get('data', {}))
        )
        db.session.add(widget)
    
    db.session.commit()
    
    return jsonify({'message': 'Widget updated', 'widget_id': widget.id})

@app.route('/api/profile/mood', methods=['POST'])
@token_required
def update_mood(current_user):
    """Update user's current mood"""
    data = request.json
    
    mood = UserMood(
        user_id=current_user.id,
        mood=data.get('mood'),
        emoji=data.get('emoji', '😊'),
        intensity=data.get('intensity', 1.0)
    )
    
    db.session.add(mood)
    db.session.commit()
    
    # Update mood widget if exists
    mood_widget = ProfileWidget.query.filter_by(
        user_id=current_user.id,
        widget_type='mood'
    ).first()
    
    if not mood_widget:
        mood_widget = ProfileWidget(
            user_id=current_user.id,
            widget_type='mood',
            widget_data=json.dumps({'auto_created': True})
        )
        db.session.add(mood_widget)
        db.session.commit()
    
    return jsonify({'message': 'Mood updated'})

@app.route('/api/profile/now-playing', methods=['POST'])
@token_required
def update_now_playing(current_user):
    """Update user's now playing music"""
    data = request.json
    
    now_playing = NowPlaying.query.filter_by(user_id=current_user.id).first()
    
    if now_playing:
        now_playing.song_title = data.get('song_title')
        now_playing.artist = data.get('artist')
        now_playing.album_art = data.get('album_art')
        now_playing.music_service = data.get('music_service')
        now_playing.is_playing = data.get('is_playing', True)
        now_playing.last_updated = datetime.now(timezone.utc)
    else:
        now_playing = NowPlaying(
            user_id=current_user.id,
            song_title=data.get('song_title'),
            artist=data.get('artist'),
            album_art=data.get('album_art'),
            music_service=data.get('music_service'),
            is_playing=data.get('is_playing', True)
        )
        db.session.add(now_playing)
    
    db.session.commit()
    
    return jsonify({'message': 'Now playing updated'})

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    # Only for admin users
    if not current_user.is_verified:
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_users = User.query.count()
    total_posts = Post.query.count()
    total_stories = Story.query.filter(
        Story.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()
    
    return jsonify({
        'total_users': total_users,
        'total_posts': total_posts,
        'active_stories': total_stories,
        'online_users': User.query.filter_by(is_online=True).count()
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

# ==================== IMPORT MIGRATE ====================
from flask_migrate import Migrate

# Initialize Migrate (do this once at the app level)
migrate = Migrate(app, db)

# ==================== INITIALIZE DATABASE ====================
with app.app_context():
    db.create_all()
    print(" Database initialized!")

    # Create demo user if database is empty
    if User.query.count() == 0:
        demo_user = User(
            username='demo',
            email='demo@synapse.com',
            password_hash=generate_password_hash('demo123'),
            avatar='',
            bio='Demo user account',
            email_verified=True,
            is_verified=True
        )
        db.session.add(demo_user)

        # Create some demo posts
        demo_posts = [
            Post(
                user_id=1,
                content='Welcome to Synapse! ',
                likes=42,
                comments_count=5
            ),
            Post(
                user_id=1,
                content='Building the future of social media ',
                image='',
                likes=128,
                comments_count=23
            ),
            Post(
                user_id=1,
                content='Connect with amazing people around the world',
                likes=95,
                comments_count=12,
                location='San Francisco, CA'
            )
        ]

        for post in demo_posts:
            db.session.add(post)

        demo_user.posts_count = len(demo_posts)
        db.session.commit()
    
        # Create demo story
        demo_story = Story(
            user_id=1,
            content='First story on Synapse!',
            emoji='',
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.session.add(demo_story)
        
        db.session.commit()
        print(" Demo data created!")
        print("   Username: demo")
        print("   Password: demo123")


if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    print("\n" + "="*50)
    print("🚀 SYNAPSE SOCIAL PLATFORM")
    print("="*50)
    print("\n📧 Email Configuration:")
    print(f"   Email: {app.config['MAIL_USERNAME']}")
    print(f"   Status: {'✅ Configured' if app.config.get('MAIL_PASSWORD') else '❌ Not configured'}")
    
    print("\n🛠️  Cutting-Edge Features:")
    print("   ✅ Ghost Mode & Privacy Controls")
    print("   ✅ AR Reality Posts & Filters") 
    print("   ✅ Life Moments with AI Mood Detection")
    print("   ✅ Custom Profile Widgets & Layouts")
    print("   ✅ Video Reactions & 360° Photos")
    
    print("\n🌐 Server Information:")
    port = int(os.environ.get('PORT', 5000))
    print(f"   Local: http://127.0.0.1:{port}")
    print(f"   Network: http://0.0.0.0:{port}")
    
    print("\n📱 Available Pages:")
    print("   / - Landing page")
    print("   /register - Sign up") 
    print("   /login - Login")
    print("   /feed - Main feed")
    print("   /moments - Life moments feed")
    print("   /explore - Discover")
    print("   /reels - Short videos")
    print("   /messages - Direct messages")
    print("   /notifications - Notifications")
    print("   /profile/<username> - User profile")
    print("   /profile/builder - Custom profile builder")
    print("   /saved - Saved posts")
    print("   /settings - Account settings")
    
    print("\n🔧 API Endpoints: /api/*")
    print("   /api/privacy/settings - Ghost mode controls")
    print("   /api/ar/filters - AR features")
    print("   /api/moments - Life moments")
    print("   /api/profile/widgets - Custom widgets")
    print("="*50 + "\n")

    # Use environment port for production
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode, allow_unsafe_werkzeug=True)
