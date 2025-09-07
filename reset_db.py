#!/usr/bin/env python3
"""
Script to reset the CGPA Tracker database
"""

from app import app, db, User, UserData, CGPAHistory

def reset_database():
    """Drop all tables and recreate them"""
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        
        print("Creating new tables...")
        db.create_all()
        
        print("Database reset complete!")
        print("You can now register new users.")

if __name__ == "__main__":
    print("CGPA Tracker - Database Reset")
    print("=" * 40)
    
    response = input("This will delete ALL data. Are you sure? (yes/no): ")
    
    if response.lower() == 'yes':
        reset_database()
    else:
        print("Database reset cancelled.")
