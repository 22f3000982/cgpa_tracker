#!/usr/bin/env python3
"""
Script to reset the CGPA Tracker database
"""

import os
import sqlite3
from datetime import datetime

def reset_database():
    """Drop all tables and recreate them using raw SQLite"""
    # Paths to check
    possible_paths = [
        os.path.join('instance', 'cgpa_tracker.db'),  # Instance folder
        'cgpa_tracker.db',                           # Current directory
    ]

    # Remove existing DB files
    for path in possible_paths:
        if os.path.exists(path):
            print(f"Removing database: {path}")
            os.remove(path)

    # Create new database
    db_path = os.path.join('instance', 'cgpa_tracker.db')
    os.makedirs('instance', exist_ok=True)

    print(f"Creating new database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
    CREATE TABLE user (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT,
        last_login TEXT,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        is_admin BOOLEAN NOT NULL DEFAULT 0
    )
    ''')

    cursor.execute('''
    CREATE TABLE user_data (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        course_data TEXT,
        target_cgpa REAL,
        updated_at TEXT,
        FOREIGN KEY (user_id) REFERENCES user (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE cgpa_history (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        cgpa REAL,
        total_credits INTEGER,
        grade_points REAL,
        recorded_at TEXT,
        FOREIGN KEY (user_id) REFERENCES user (id)
    )
    ''')

    # Create admin user
    current_time = datetime.now().isoformat()

    cursor.execute(
        "INSERT INTO user (username, email, password_hash, created_at, is_active, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
        ('admin', 'admin@example.com', '4129', current_time, 1, 1)
    )

    # Commit and close
    conn.commit()
    conn.close()
    
    print("Database reset complete!")
    print("Admin user created:")
    print("Username: admin")
    print("Password: 4129")

if __name__ == "__main__":
    print("CGPA Tracker - Database Reset")
    print("=" * 40)
    
    response = input("This will delete ALL data. Are you sure? (yes/no): ")
    
    if response.lower() == 'yes':
        reset_database()
    else:
        print("Database reset cancelled.")
