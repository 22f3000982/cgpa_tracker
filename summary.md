# CGPA Tracker App - Simplified Technical Documentation

## Overview
A simple CGPA tracker for IIT Madras BS (Bachelor of Science) program students. Users login with username/email and password to view their personalized dashboard with stored academic data.

## Database Schema (SQLite)

### 1. Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active INTEGER DEFAULT 1
);
```

### 2. User Data Table
```sql
CREATE TABLE user_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    course_data TEXT, -- JSON string containing course grades and information
    target_cgpa REAL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### 3. CGPA History Table
```sql
CREATE TABLE cgpa_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cgpa REAL NOT NULL,
    total_credits INTEGER NOT NULL,
    grade_points REAL NOT NULL,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Core Features

### 1. User Authentication System
- **User Registration**: Username/email and password
- **User Login**: JWT token authentication
- **Password Hashing**: bcryptjs with salt rounds
- **Dashboard Access**: Personalized data display after login

#### Login Flow:
```javascript
// 1. User enters username/email and password
// 2. System verifies credentials
// 3. JWT token generated and stored
// 4. User redirected to dashboard
// 5. Dashboard loads user's stored CGPA data

// Password verification
const isValidPassword = await bcrypt.compare(password, user.password_hash);

// JWT token generation
const token = jwt.sign(
    { userId: user.id, username: user.username },
    process.env.JWT_SECRET || 'dev-secret-key',
    { expiresIn: '7d' }
);
```

### 2. CGPA Calculation System

#### Grade Point Mapping:
```javascript
const gradePoints = { S: 10, A: 9, B: 8, C: 7, D: 6, E: 4 };
```

#### CGPA Formula:
```
CGPA = Σ(Grade Points × Credits) / Σ(Credits)
```

#### Credit Structure for IIT Madras BS Program:

### Foundation Level (32 credits total - 8 courses × 4 credits each):
1. **Mathematics for Data Science I** (BSMA1001) - 4 credits
2. **Statistics for Data Science I** (BSMA1002) - 4 credits  
3. **Computational Thinking** (BSCS1001) - 4 credits
4. **English I** (BSHS1001) - 4 credits
5. **Mathematics for Data Science II** (BSMA1003) - 4 credits
6. **Statistics for Data Science II** (BSMA1004) - 4 credits
7. **Programming in Python** (BSCS1002) - 4 credits
8. **English II** (BSHS1002) - 4 credits

### Programming Diploma (27 credits total):
1. **Database Management Systems** (BSCS2001) - 4 credits
2. **Programming, Data Structures and Algorithms using Python** (BSCS2002) - 4 credits
3. **Modern Application Development I** (BSCS2003) - 4 credits
4. **Modern Application Development I - Project** (BSCS2003P) - 2 credits
5. **Programming Concepts using Java** (BSCS2005) - 4 credits
6. **Modern Application Development II** (BSCS2006) - 4 credits
7. **Modern Application Development II - Project** (BSCS2006P) - 2 credits
8. **System Commands** (BSSE2001) - 3 credits

### Data Science Diploma (28 credits total):
1. **Statistics for Data Science II** (BSMA1004) - 4 credits
2. **Introduction to Data Science** (BSCS2004) - 4 credits
3. **Business Data Management** (BSCS2007) - 4 credits
4. **Business Analytics** (BSCS2008) - 4 credits
5. **Machine Learning Practice** (BSCS2009) - 2 credits
6. **Tools in Data Science** (BSCS2010) - 3 credits
7. **Machine Learning Foundations** (BSCS2011) - 4 credits
8. **Machine Learning Techniques** (BSCS2012) - 3 credits

### Degree Core Courses (4 credits each):
- Additional core courses as per degree requirements

### Elective Courses (4 credits each):
- Various elective options available for specialization

#### CGPA Calculation Function:
```javascript
function calculateStats(courseData) {
    let totalPoints = 0;
    let totalCredits = 0;
    let completedCourses = 0;
    const gradeDistribution = { S: 0, A: 0, B: 0, C: 0, D: 0, E: 0 };

    if (!courseData || !courseData.courses) {
        return { cgpa: 0, totalCredits: 0, completedCourses: 0, gradeDistribution };
    }

    Object.entries(courseData.courses).forEach(([courseId, data]) => {
        if (data.grade && gradePoints[data.grade]) {
            const credits = getCreditsForCourse(courseId);
            totalPoints += gradePoints[data.grade] * credits;
            totalCredits += credits;
            completedCourses++;
            gradeDistribution[data.grade]++;
        }
    });

    const cgpa = totalCredits > 0 ? (totalPoints / totalCredits) : 0;

    return {
        cgpa: parseFloat(cgpa.toFixed(2)),
        totalCredits,
        completedCourses,
        gradeDistribution,
        totalPoints
    };
}
```

### 3. Dashboard Display System

#### User Dashboard Features:
- **Current CGPA**: Real-time calculation from stored grades
- **Total Credits**: Sum of completed course credits
- **Grade Distribution**: Visual representation of grades (S, A, B, C, D, E)
- **Progress Tracking**: Percentage completion toward degree
- **CGPA History**: Historical CGPA trend over time

#### Dashboard Data Loading:
```javascript
// After successful login, load user's stored data
async function loadUserDashboard(userId) {
    // Get user's course data
    const userData = await getUserData(userId);
    
    // Calculate current stats
    const stats = calculateStats(userData.course_data);
    
    // Get CGPA history
    const cgpaHistory = await getCGPAHistory(userId);
    
    // Display on dashboard
    displayDashboard({
        currentCGPA: stats.cgpa,
        totalCredits: stats.totalCredits,
        completedCourses: stats.completedCourses,
        gradeDistribution: stats.gradeDistribution,
        cgpaHistory: cgpaHistory,
        progressPercentage: (stats.totalCredits / 142) * 100
    });
}
```

### 4. Course Management

#### Course Data Structure:
```javascript
// Stored in user_data.course_data as JSON
{
    "courses": {
        "foundation-1": { "grade": "A", "courseName": "Mathematics for Data Science I" },
        "foundation-2": { "grade": "S", "courseName": "Statistics for Data Science I" },
        "programming-1": { "grade": "B", "courseName": "Database Management Systems" }
        // ... more courses
    },
    "targetCGPA": 8.5
}
```

#### Credit Calculation:
```javascript
function getCreditsForCourse(courseId) {
    const [section, index] = courseId.split('-');
    
    const creditMap = {
        // Foundation Level - All 4 credits
        foundation: 4,
        
        // Programming Diploma
        programming: {
            '1': 4, // Database Management Systems
            '2': 4, // Programming, Data Structures and Algorithms using Python
            '3': 4, // Modern Application Development I
            '4': 2, // Modern Application Development I - Project
            '5': 4, // Programming Concepts using Java
            '6': 4, // Modern Application Development II
            '7': 2, // Modern Application Development II - Project
            '8': 3, // System Commands
            default: 4
        },
        
        // Data Science Diploma
        dataScience: {
            '1': 4, // Statistics for Data Science II
            '2': 4, // Introduction to Data Science
            '3': 4, // Business Data Management
            '4': 4, // Business Analytics
            '5': 2, // Machine Learning Practice
            '6': 3, // Tools in Data Science
            '7': 4, // Machine Learning Foundations
            '8': 3, // Machine Learning Techniques
            default: 4
        },
        
        // Degree Core and Electives
        degreeCore: 4,
        elective: 4
    };
    
    if (section === 'programming') {
        return creditMap.programming[index] || creditMap.programming.default;
    } else if (section === 'dataScience') {
        return creditMap.dataScience[index] || creditMap.dataScience.default;
    } else {
        return creditMap[section] || 4;
    }
}

// Course Name Mapping for Display
const courseNames = {
    // Foundation Level
    'foundation-1': 'Mathematics for Data Science I',
    'foundation-2': 'Statistics for Data Science I',
    'foundation-3': 'Computational Thinking',
    'foundation-4': 'English I',
    'foundation-5': 'Mathematics for Data Science II',
    'foundation-6': 'Statistics for Data Science II',
    'foundation-7': 'Programming in Python',
    'foundation-8': 'English II',
    
    // Programming Diploma
    'programming-1': 'Database Management Systems',
    'programming-2': 'Programming, Data Structures and Algorithms using Python',
    'programming-3': 'Modern Application Development I',
    'programming-4': 'Modern Application Development I - Project',
    'programming-5': 'Programming Concepts using Java',
    'programming-6': 'Modern Application Development II',
    'programming-7': 'Modern Application Development II - Project',
    'programming-8': 'System Commands',
    
    // Data Science Diploma
    'dataScience-1': 'Statistics for Data Science II',
    'dataScience-2': 'Introduction to Data Science',
    'dataScience-3': 'Business Data Management',
    'dataScience-4': 'Business Analytics',
    'dataScience-5': 'Machine Learning Practice',
    'dataScience-6': 'Tools in Data Science',
    'dataScience-7': 'Machine Learning Foundations',
    'dataScience-8': 'Machine Learning Techniques'
};
```

## API Endpoints

### Authentication:
- `POST /api/auth/login` - User login (username/email + password)
- `POST /api/auth/register` - User registration
- `GET /api/auth/verify` - Token verification

### CGPA Data:
- `GET /api/user/data` - Fetch user's course data and CGPA
- `POST /api/user/data` - Save/update user's course grades

## User Flow

### 1. Registration:
```
User visits app → Register page → Enter username/email + password → Account created → Redirect to login
```

### 2. Login & Dashboard:
```
User visits app → Login page → Enter credentials → JWT token generated → Dashboard loads with stored CGPA data
```

### 3. Dashboard Display:
```
Token verified → User ID extracted → Database query for user's course data → CGPA calculated → Dashboard populated
```

## Frontend Features

### 1. Login/Registration Forms:
- Username/email input field
- Password input with validation
- Remember me functionality
- Error handling for invalid credentials

### 2. CGPA Dashboard:
- Current CGPA display (large, prominent)
- Total credits earned
- Grade distribution chart
- Progress bar toward degree completion
- CGPA history trend line

### 3. Course Grade Entry:
- Course selection dropdown
- Grade input (S, A, B, C, D, E)
- Real-time CGPA update
- Save/update functionality

## Flask Implementation Guide

### 1. Database Models:
```python
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import json

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationship
    user_data = db.relationship('UserData', backref='user', lazy=True)
    cgpa_history = db.relationship('CGPAHistory', backref='user', lazy=True)

class UserData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_data = db.Column(db.Text)  # JSON string
    target_cgpa = db.Column(db.Float)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class CGPAHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cgpa = db.Column(db.Float, nullable=False)
    total_credits = db.Column(db.Integer, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
```

### 2. Authentication Routes:
```python
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_email = data.get('username')
    password = data.get('password')
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == username_or_email) | 
        (User.email == username_or_email)
    ).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        })
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/user/data', methods=['GET'])
@jwt_required()
def get_user_data():
    user_id = get_jwt_identity()
    user_data = UserData.query.filter_by(user_id=user_id).first()
    
    if not user_data:
        return jsonify({'course_data': {}, 'target_cgpa': None})
    
    course_data = json.loads(user_data.course_data) if user_data.course_data else {}
    
    return jsonify({
        'course_data': course_data,
        'target_cgpa': user_data.target_cgpa
    })
```

### 3. CGPA Calculation:
```python
def calculate_cgpa(course_data):
    grade_points = {'S': 10, 'A': 9, 'B': 8, 'C': 7, 'D': 6, 'E': 4}
    
    total_points = 0
    total_credits = 0
    
    if not course_data or 'courses' not in course_data:
        return 0, 0
    
    for course_id, course_info in course_data['courses'].items():
        if 'grade' in course_info and course_info['grade'] in grade_points:
            credits = get_credits_for_course(course_id)
            total_points += grade_points[course_info['grade']] * credits
            total_credits += credits
    
    cgpa = total_points / total_credits if total_credits > 0 else 0
    return round(cgpa, 2), total_credits
```

### 4. Required Flask Packages:
```bash
pip install Flask Flask-SQLAlchemy Flask-JWT-Extended Flask-Bcrypt Flask-CORS
```

### 5. App Configuration:
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgpa_tracker.db'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)
```

This simplified documentation focuses only on the CGPA tracking functionality with user authentication and personalized dashboard display.
