from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_migrate import migrate
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import jwt
import secrets
import random
from datetime import datetime, timedelta, timezone
from functools import wraps
import os
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///synapse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'johnkravin9@gmail.com'
app.config['MAIL_PASSWORD'] = 'bqvh expq bnzt nmww'
app.config['MAIL_DEFAULT_SENDER'] = 'johnkravin9@gmail.com'
#o
# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'your-google-client-id')

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ==================== DATABASE MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    phone = db.Column(db.String(20), unique=True)
    avatar = db.Column(db.String(10), default='🚀')
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

# ==================== HELPER FUNCTIONS ====================

def generate_verification_code():
    return str(random.randint(100000, 999999))

def send_verification_email(email, code):
    try:
        msg = Message(
            subject='Verify Your Synapse Account',
            recipients=[email]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h1>⚡ Welcome to Synapse!</h1>
            <p style="font-size: 18px;">Your verification code is:</p>
            <h2 style="background: white; color: #667eea; padding: 15px; border-radius: 10px; text-align: center; letter-spacing: 5px;">
                {code}
            </h2>
            <p>This code expires in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </div>
        '''
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
        # 1️⃣ Try to get token from Authorization header
        header_token = request.headers.get('Authorization')
        raw_token = None

        if header_token:
            parts = header_token.split(" ")
            if len(parts) == 2:
                raw_token = parts[1]

        # 2️⃣ If no header token, try cookie token
        if not raw_token:
            raw_token = request.cookies.get('synapse_token')

        # 3️⃣ If still no token, reject
        if not raw_token:
            return jsonify({'error': 'Token is missing'}), 401

        # 4️⃣ Validate token
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
        avatar=data.get('avatar', '🚀')
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
    
    # Read file and convert to base64
    file_data = file.read()
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
        'size': len(file_data)
    })
#==============ƙ=ƙ(=====jj++++=friends routes++++++++++========

# Add Friend Request Endpoints
@app.route('/api/friends/request/<int:user_id>', methods=['POST'])
@token_required
def send_friend_request(current_user, user_id):
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot send request to yourself'}), 400
    
    existing = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=user_id
    ).first()
    
    if existing:
        return jsonify({'error': 'Request already sent'}), 400
    
    request_obj = FriendRequest(
        sender_id=current_user.id,
        receiver_id=user_id,
        status='pending'
    )
    db.session.add(request_obj)
    
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
    request_obj = FriendRequest.query.get_or_404(request_id)
    
    if request_obj.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    request_obj.status = 'accepted'
    
    # Create Follow relationships both ways
    follow1 = Follow(follower_id=request_obj.sender_id, following_id=current_user.id)
    follow2 = Follow(follower_id=current_user.id, following_id=request_obj.sender_id)
    
    db.session.add(follow1)
    db.session.add(follow2)
    
    # Update counts
    sender = User.query.get(request_obj.sender_id)
    sender.following_count += 1
    current_user.following_count += 1
    sender.followers_count += 1
    current_user.followers_count += 1
    
    db.session.commit()
    
    return jsonify({'message': 'Friend request accepted!'})

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
            'timestamp': req.created_at.strftime('%Y-%m-%d %H:%M:%S')
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

from flask import request, jsonify
from werkzeug.utils import secure_filename
import os

@app.route('/api/reels', methods=['POST'])
def upload_reel():
    if 'file' not in request.files:
        return jsonify({'error': '❌ No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '❌ No selected file'}), 400

    filename = secure_filename(file.filename)
    file.save(os.path.join('uploads', filename))  # save file

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
            'title': reel.title,
            'video_url': reel.video_url,
            'thumbnail': reel.thumbnail,
            'likes': reel.likes,
            'comments': reel.comments_count,
            'views': reel.views
        })
    
    return jsonify({
        'reels': reels_data,
        'has_next': reels.has_next
    })

@app.route('/api/reels', methods=['POST'])
@token_required
def create_reel(current_user):
    data = request.json

    reel = Reel(
        user_id=current_user.id,
        title=data.get('title'),
        video_url=data.get('video_url', data.get('thumbnail', '')),  # Use video_url if present, else thumbnail
        thumbnail=data.get('thumbnail', '🎬')
    )

    db.session.add(reel)
    current_user.points += 20
    db.session.commit()

    return jsonify({
        'message': 'Reel created!',
        'reel_id': reel.id
    }), 201

@app.route('/api/reels/<int:reel_id>/comment', methods=['POST'])
@token_required
def comment_reel(current_user, reel_id):
    data = request.get_json()
    text = data.get('text')
    comment = ReelComment(reel_id=reel_id, user_id=current_user.id, text=text)
    db.session.add(comment)
    db.session.commit()
    return jsonify({"message": "Comment added"})

@app.route('/api/reels/<int:reel_id>/share', methods=['POST'])
@token_required
def share_reel(current_user, reel_id):
    # Example: Copy reel to user feed
    original = Reel.query.get(reel_id)
    if not original:
        return jsonify({"error": "Reel not found"}), 404
    shared_reel = Reel(user_id=current_user.id, media_url=original.media_url, media_type=original.media_type, caption=original.caption)
    db.session.add(shared_reel)
    db.session.commit()
    return jsonify({"message": "Reel shared"})

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

‎@app.route('/profile/me')
‎def profile_me():
‎    # Check if logged in via cookie/session
‎    token = request.cookies.get('synapse_token')
‎    if not token:
‎        # Try from localStorage (handled in JS)
‎        return render_template('profile_redirect.html')
‎    
‎    try:
‎        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
‎        user = User.query.get(data['user_id'])
‎        if user:
‎            return redirect(f'/profile/{user.username}')
‎    except:
‎        pass
‎    
‎    return redirect('/login')

# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join')
def handle_join(data):
    room = f"user_{data['user_id']}"
    join_room(room)
    emit('joined', {'room': room})

@socketio.on('leave')
def handle_leave(data):
    room = f"user_{data['user_id']}"
    leave_room(room)
    emit('left', {'room': room})

@socketio.on('user_online')
def handle_user_online(data):
    user_id = data.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.is_online = True
            user.last_seen = datetime.now(timezone.utc)
            db.session.commit()
            emit('user_status', {'user_id': user_id, 'online': True})

@socketio.on('typing')
def handle_typing(data):
    emit('user_typing', data, include_self=False)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    message = Message(
        sender_id=sender_id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    emit('receive_message', {
        'id': message.id,
        'sender_id': sender_id,
        'content': content,
        'timestamp': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }, room=f'user_{receiver_id}')

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
    print("✅ Database initialized!")

    # Create demo user if database is empty
    if User.query.count() == 0:
        demo_user = User(
            username='demo',
            email='demo@synapse.com',
            password_hash=generate_password_hash('demo123'),
            avatar='🚀',
            bio='Demo user account',
            email_verified=True,
            is_verified=True
        )
        db.session.add(demo_user)

        # Create some demo posts
        demo_posts = [
            Post(
                user_id=1,
                content='Welcome to Synapse! 🚀',
                likes=42,
                comments_count=5
            ),
            Post(
                user_id=1,
                content='Building the future of social media 💡',
                image='🎨',
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
            emoji='🎉',
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.session.add(demo_story)
        
        db.session.commit()
        print("✅ Demo data created!")
        print("   Username: demo")
        print("   Password: demo123")

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 SYNAPSE SOCIAL PLATFORM")
    print("="*50)
    print("\n📧 Email Configuration:")
    print(f"   Email: {app.config['MAIL_USERNAME']}")
    print(f"   Status: {'✅ Configured' if app.config['MAIL_PASSWORD'] else '❌ Not configured'}")
    print("\n🌐 Server Information:")
    print("   Local: http://127.0.0.1:5000")
    print("   Network: http://0.0.0.0:5000")
    print("\n📱 Available Pages:")
    print("   / - Landing page")
    print("   /register - Sign up")
    print("   /login - Login")
    print("   /feed - Main feed")
    print("   /explore - Discover")
    print("   /reels - Short videos")
    print("   /messages - Direct messages")
    print("   /notifications - Notifications")
    print("   /profile/<username> - User profile")
    print("   /saved - Saved posts")
    print("   /settings - Account settings")
    print("\n🔧 API Endpoints: /api/*")
    print("="*50 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
