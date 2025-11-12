from app import app, db, User, Post, Story, Reel, Media, Like, Comment
from datetime import datetime, timedelta
import os

# Remove existing database
if os.path.exists('synapse.db'):
    os.remove('synapse.db')

with app.app_context():
    # Create all tables
    db.create_all()
    print("✅ Database tables created!")
    
    # Create a demo user
    demo_user = User(
        username='demo',
        email='demo@example.com',
        password_hash='demo123',  # In real app, use proper hashing
        avatar='🚀',
        points=100
    )
    
    try:
        db.session.add(demo_user)
        db.session.commit()
        print("✅ Demo user created!")
        
        # Create some sample posts
        post1 = Post(
            user_id=demo_user.id,
            content='Welcome to Synapse Social! 🎉 This is an amazing platform for connecting with people.',
            created_at=datetime.utcnow()
        )
        
        post2 = Post(
            user_id=demo_user.id,
            content='Just exploring all the great features here. The interface is beautiful! ✨',
            created_at=datetime.utcnow() - timedelta(hours=2)
        )
        
        db.session.add_all([post1, post2])
        db.session.commit()
        print("✅ Sample posts created!")
        
        # Create sample stories
        story1 = Story(
            user_id=demo_user.id,
            content='Hello everyone! 👋',
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        
        db.session.add(story1)
        db.session.commit()
        print("✅ Sample story created!")
        
        print("\\n============================================")
        print("🎉 DATABASE INITIALIZED SUCCESSFULLY!")
        print("============================================")
        print("📊 Created:")
        print("   - Database tables")
        print("   - Demo user (demo)")
        print("   - Sample posts")
        print("   - Sample story")
        print("============================================\\n")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.session.rollback()

