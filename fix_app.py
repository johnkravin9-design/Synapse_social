# Fix for get_posts function
@app.route('/api/posts', methods=['GET'])
@token_required
def get_posts(current_user):
    try:
        posts = Post.query.order_by(Post.created_at.desc()).all()
        posts_data = []
        
        for post in posts:
            # Get the user who created the post
            user = User.query.get(post.user_id)  # Use post.user_id, not user_id
            
            posts_data.append({
                'id': post.id,
                'content': post.content,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar
                },
                'created_at': post.created_at.isoformat(),
                'likes_count': post.likes_count or 0,
                'comments_count': post.comments_count or 0,
                'media': post.media  # If you have media field
            })
        
        return jsonify({'posts': posts_data})
        
    except Exception as e:
        print(f"Error in get_posts: {e}")
        return jsonify({'error': 'Failed to fetch posts'}), 500

# Fix for get_reels function
@app.route('/api/reels', methods=['GET'])
@token_required
def get_reels(current_user):
    try:
        reels = Reel.query.order_by(Reel.created_at.desc()).all()
        reels_data = []
        
        for reel in reels:
            user = User.query.get(reel.user_id)
            media = Media.query.get(reel.media_id) if reel.media_id else None
            
            reels_data.append({
                'id': reel.id,
                'caption': reel.caption,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'avatar': user.avatar
                },
                'media': {
                    'id': media.id if media else None,
                    'file_path': media.file_path if media else None,
                    'file_type': media.file_type if media else None
                } if media else None,
                'created_at': reel.created_at.isoformat(),
                'likes_count': reel.likes_count or 0,
                'comments_count': reel.comments_count or 0,
                'views_count': reel.views_count or 0
            })
        
        return jsonify({'reels': reels_data})
        
    except Exception as e:
        print(f"Error in get_reels: {e}")
        return jsonify({'error': 'Failed to fetch reels'}), 500

# Updated Reel model (if not already defined)
class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_id = db.Column(db.Integer, db.ForeignKey('media.id'), nullable=False)
    caption = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    shares_count = db.Column(db.Integer, default=0)
    views_count = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', backref=db.backref('reels', lazy=True))
    media = db.relationship('Media', backref=db.backref('reel', lazy=True))
