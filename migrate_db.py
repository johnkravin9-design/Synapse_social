#!/usr/bin/env python3
"""
Database Migration Script
Adds missing columns to existing database
"""

import sqlite3
import sys

def migrate_database():
    try:
        conn = sqlite3.connect('synapse.db')
        cursor = conn.cursor()
        
        print("🔧 Starting database migration...")
        
        # Check and add missing columns to Story table
        try:
            cursor.execute("ALTER TABLE story ADD COLUMN image VARCHAR(255)")
            print("✅ Added 'image' column to Story table")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⏭️  'image' column already exists in Story table")
            else:
                print(f"⚠️  Could not add 'image' to Story: {e}")
        
        # Check and add missing columns to User table
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN is_verified BOOLEAN DEFAULT 0")
            print("✅ Added 'is_verified' column to User table")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⏭️  'is_verified' column already exists in User table")
            else:
                print(f"⚠️  Could not add 'is_verified' to User: {e}")
        
        # Check and add missing columns to User table (bio)
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN bio TEXT DEFAULT 'Hey there! I am using Synapse'")
            print("✅ Added 'bio' column to User table")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⏭️  'bio' column already exists in User table")
            else:
                print(f"⚠️  Could not add 'bio' to User: {e}")
        
        # Check and add missing columns to User table (website)
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN website VARCHAR(255)")
            print("✅ Added 'website' column to User table")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⏭️  'website' column already exists in User table")
            else:
                print(f"⚠️  Could not add 'website' to User: {e}")
        
        # Commit changes
        conn.commit()
        print("\n✅ Migration completed successfully!")
        print("📊 Database is now up to date")
        
        # Show current schema
        print("\n📋 Current User table columns:")
        cursor.execute("PRAGMA table_info(user)")
        for row in cursor.fetchall():
            print(f"   - {row[1]} ({row[2]})")
        
        print("\n📋 Current Story table columns:")
        cursor.execute("PRAGMA table_info(story)")
        for row in cursor.fetchall():
            print(f"   - {row[1]} ({row[2]})")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("="*60)
    print("🚀 SYNAPSE DATABASE MIGRATION")
    print("="*60)
    print()
    
    migrate_database()
    
    print()
    print("="*60)
    print("✨ You can now restart your Flask app!")
    print("   python app.py")
    print("="*60)
