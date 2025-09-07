from flask import Flask, request, jsonify, render_template, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import tempfile

app = Flask(__name__)

# Configuration for Vercel - use in-memory SQLite for serverless environment
is_vercel = os.environ.get('VERCEL_REGION') is not None
if is_vercel:
    # We're on Vercel, use in-memory SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    print("Using in-memory SQLite database for Vercel deployment")
else:
    # Local development
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cgpa_tracker.db')
    print(f"Using SQLite database: {app.config['SQLALCHEMY_DATABASE_URI']}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-production-secret-key-change-this')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_ALGORITHM'] = 'HS256'

# Enable debug mode for better error reporting in development
app.debug = not is_vercel and os.environ.get('FLASK_ENV') != 'production'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    user_data = db.relationship('UserData', backref='user', lazy=True)
    cgpa_history = db.relationship('CGPAHistory', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class UserData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_data = db.Column(db.Text)  # JSON string
    target_cgpa = db.Column(db.Float)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class CGPAHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cgpa = db.Column(db.Float, nullable=False)
    total_credits = db.Column(db.Integer, nullable=False)
    grade_points = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Grade Points and Course Information
GRADE_POINTS = {'S': 10, 'A': 9, 'B': 8, 'C': 7, 'D': 6, 'E': 4}

COURSE_NAMES = {
    # Foundation Level
    'foundation-1': 'Mathematics for Data Science I',
    'foundation-2': 'Statistics for Data Science I',
    'foundation-3': 'Computational Thinking',
    'foundation-4': 'English I',
    'foundation-5': 'Mathematics for Data Science II',
    'foundation-6': 'Statistics for Data Science II',
    'foundation-7': 'Programming in Python',
    'foundation-8': 'English II',
    
    # Programming Diploma
    'programming-1': 'Database Management Systems',
    'programming-2': 'Programming, Data Structures and Algorithms using Python',
    'programming-3': 'Modern Application Development I',
    'programming-4': 'Modern Application Development I - Project',
    'programming-5': 'Programming Concepts using Java',
    'programming-6': 'Modern Application Development II',
    'programming-7': 'Modern Application Development II - Project',
    'programming-8': 'System Commands',
    
    # Data Science Diploma - Core Courses
    'BSCS2004': 'Machine Learning Foundations',
    'BSMS2001': 'Business Data Management',
    'BSCS2007': 'Machine Learning Techniques',
    'BSCS2008': 'Machine Learning Practice',
    'BSCS2008P': 'Machine Learning Practice - Project',
    'BSSE2002': 'Tools in Data Science',
    
    # Data Science Diploma - Option 1 (Business Analytics Path)
    'BSMS2002': 'Business Analytics',
    'BSMS2001P': 'Business Data Management - Project',
    
    # Data Science Diploma - Option 2 (Generative AI Path)
    'BSDA2001': 'Introduction to Deep Learning and Generative AI',
    'BSDA2001P': 'Deep Learning and Generative AI - Project'
}

def get_credits_for_course(course_id):
    """Get credits for a specific course based on course ID"""
    if not course_id:
        return 4
    
    # Handle old format (section-index) for backward compatibility
    if '-' in course_id:
        section, index = course_id.split('-')
        
        # Programming Diploma special cases
        if section == 'programming':
            programming_credits = {
                '4': 2,  # Modern Application Development I - Project
                '7': 2,  # Modern Application Development II - Project
                '8': 3,  # System Commands
            }
            return programming_credits.get(index, 4)
        
        # Data Science Diploma special cases (old format)
        elif section == 'dataScience':
            datascience_credits = {
                '5': 2,  # Machine Learning Practice
                '6': 3,  # Tools in Data Science
                '8': 3,  # Machine Learning Techniques
            }
            return datascience_credits.get(index, 4)
    
    # Handle new course ID format (e.g., BSCS2004, BSMS2001P)
    else:
        # Project courses have 2 credits
        if course_id.endswith('P'):
            return 2
        
        # Specific course credit mappings
        course_credits = {
            'BSSE2002': 3,  # Tools in Data Science
            # All other courses default to 4 credits
        }
        return course_credits.get(course_id, 4)
    
    # Foundation and other courses are 4 credits
    return 4

def calculate_stats(course_data):
    """Calculate CGPA and other statistics from course data"""
    total_points = 0
    total_credits = 0
    completed_courses = 0
    grade_distribution = {'S': 0, 'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0}

    if not course_data or 'courses' not in course_data:
        return {
            'cgpa': 0,
            'totalCredits': 0,
            'completedCourses': 0,
            'gradeDistribution': grade_distribution,
            'totalPoints': 0
        }

    for course_id, course_info in course_data['courses'].items():
        if 'grade' in course_info and course_info['grade'] in GRADE_POINTS:
            credits = get_credits_for_course(course_id)
            grade_points = GRADE_POINTS[course_info['grade']]
            
            total_points += grade_points * credits
            total_credits += credits
            completed_courses += 1
            grade_distribution[course_info['grade']] += 1

    cgpa = (total_points / total_credits) if total_credits > 0 else 0

    return {
        'cgpa': round(cgpa, 3),
        'totalCredits': total_credits,
        'completedCourses': completed_courses,
        'gradeDistribution': grade_distribution,
        'totalPoints': total_points
    }

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        # Make sure the database is initialized for this request
        with app.app_context():
            try:
                # Force table creation for serverless environment
                if os.environ.get('VERCEL_REGION'):
                    db.create_all()
                    print("Tables created for registration endpoint")
            except Exception as table_error:
                print(f"Table creation error (non-critical): {table_error}")

        # Get and validate request data
        try:
            data = request.get_json()
            if not data:
                return jsonify({'message': 'Invalid JSON data'}), 400
        except Exception as json_error:
            print(f"Error parsing JSON: {json_error}")
            return jsonify({'message': 'Invalid request format'}), 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        print(f"DEBUG REGISTER: Attempting registration for: {username}, {email}")

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Check if user already exists - with simplified logic for serverless
        try:
            # Simple query to check if user exists by username
            existing_user = User.query.filter_by(username=username).first()
            
            if existing_user:
                return jsonify({'message': 'Username already exists. Please choose a different username.'}), 409
            
            # If email provided, check that too
            if email:
                existing_email = User.query.filter_by(email=email).first()
                if existing_email:
                    return jsonify({'message': 'Email already exists. Please use a different email.'}), 409
        except Exception as check_error:
            print(f"Error checking existing user: {str(check_error)}")
            # Continue anyway since this might be a brand new database

        # Create new user with safer error handling
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            print("Password hashed successfully")
            
            new_user = User(
                username=username,
                email=email,
                password_hash=password_hash
            )
            print("User object created")
            
            db.session.add(new_user)
            print("User added to session")
            
            db.session.commit()
            print(f"DEBUG REGISTER: User created successfully: {username}")
            
            # Return success response
            return jsonify({
                'message': 'User created successfully',
                'username': username
            }), 201
            
        except Exception as db_error:
            print(f"Error during user creation/commit: {str(db_error)}")
            db.session.rollback()
            # Return a cleaner error message to the client
            return jsonify({'message': 'Could not create user account. Please try again later.'}), 500

    except Exception as e:
        print(f"DEBUG REGISTER ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        
        try:
            db.session.rollback()
        except:
            pass
            
        return jsonify({
            'message': 'Registration failed',
            'error': 'An unexpected error occurred during registration'
        }), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        # For serverless environment, make sure tables and admin user exist
        if os.environ.get('VERCEL_REGION'):
            try:
                # Force database initialization for each login attempt in serverless
                with app.app_context():
                    db.create_all()
                    # Special handling for admin user
                    admin_exists = User.query.filter_by(username='admin').first() is not None
                    if not admin_exists:
                        print("Admin user doesn't exist, creating it now...")
                        password_hash = bcrypt.generate_password_hash('4129').decode('utf-8')
                        admin = User(
                            username='admin',
                            email='admin@cgpatracker.com',
                            password_hash=password_hash,
                            is_admin=True
                        )
                        db.session.add(admin)
                        db.session.commit()
                        print("Admin user created for login attempt")
            except Exception as init_error:
                print(f"Error in login database initialization: {init_error}")
                # Continue anyway, maybe tables already exist

        # Parse request data
        try:
            data = request.get_json()
            if not data:
                return jsonify({'message': 'Invalid JSON data'}), 400
        except Exception as json_error:
            print(f"Error parsing login JSON: {json_error}")
            return jsonify({'message': 'Invalid request format'}), 400

        username_or_email = data.get('username')
        password = data.get('password')

        print(f"DEBUG LOGIN: Attempting login for: {username_or_email}")

        if not username_or_email or not password:
            return jsonify({'message': 'Username/email and password are required'}), 400

        # Special handling for admin login - hardcoded check as a fallback
        if username_or_email == 'admin' and password == '4129':
            print("Admin credentials matched, searching for admin user...")
            # Try to find admin user or create if not found
            try:
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    # Create admin user if it doesn't exist
                    password_hash = bcrypt.generate_password_hash('4129').decode('utf-8')
                    admin_user = User(
                        username='admin',
                        email='admin@cgpatracker.com',
                        password_hash=password_hash,
                        is_admin=True,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.session.add(admin_user)
                    db.session.commit()
                    print("Admin user created during login")
                
                # Update last login for admin
                admin_user.last_login = datetime.now(timezone.utc)
                db.session.commit()
                
                # Create access token for admin
                access_token = create_access_token(identity=str(admin_user.id))
                print("Admin login successful with special handling")
                
                return jsonify({
                    'access_token': access_token,
                    'user': admin_user.to_dict(),
                    'message': 'Admin login successful'
                })
            except Exception as admin_error:
                print(f"Error in admin special handling: {admin_error}")
                # Fall through to regular login flow
        
        try:
            # Find user by username or email
            user = User.query.filter(
                (User.username == username_or_email) | 
                (User.email == username_or_email)
            ).first()

            print(f"DEBUG LOGIN: User found: {user is not None}")

            if user and bcrypt.check_password_hash(user.password_hash, password):
                print(f"DEBUG LOGIN: Password check passed for user: {user.username}")
                # Update last login
                user.last_login = datetime.now(timezone.utc)
                db.session.commit()

                # Create access token
                access_token = create_access_token(identity=str(user.id))
                print(f"DEBUG LOGIN: Token created successfully")

                return jsonify({
                    'access_token': access_token,
                    'user': user.to_dict(),
                    'message': 'Login successful'
                })

            print(f"DEBUG LOGIN: Authentication failed")
            return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as query_error:
            print(f"Error during user query: {query_error}")
            return jsonify({'message': 'Login failed due to database error'}), 500

    except Exception as e:
        print(f"DEBUG LOGIN ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user and user.is_active:
            return jsonify({'valid': True, 'user': user.to_dict()})
        
        return jsonify({'valid': False}), 401
    
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 401

@app.route('/api/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    try:
        user_id = int(get_jwt_identity())
        print(f"DEBUG TEST: User ID: {user_id}")
        return jsonify({'user_id': user_id, 'message': 'Authentication working'})
    except Exception as e:
        print(f"DEBUG TEST: Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/data', methods=['GET'])
@jwt_required()
def get_user_data():
    try:
        user_id = int(get_jwt_identity())
        print(f"DEBUG: User ID from token: {user_id}")  # Debug line
        
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401
            
        user_data = UserData.query.filter_by(user_id=user_id).first()

        if not user_data:
            print(f"DEBUG: No user data found for user_id: {user_id}")  # Debug line
            return jsonify({
                'course_data': {'courses': {}},
                'target_cgpa': None,
                'stats': calculate_stats({'courses': {}})
            })

        course_data = json.loads(user_data.course_data) if user_data.course_data else {'courses': {}}
        stats = calculate_stats(course_data)

        return jsonify({
            'course_data': course_data,
            'target_cgpa': user_data.target_cgpa,
            'stats': stats
        })

    except Exception as e:
        print(f"DEBUG: Error in get_user_data: {str(e)}")  # Debug line
        return jsonify({'message': 'Failed to fetch user data', 'error': str(e)}), 500

@app.route('/api/user/data', methods=['POST'])
@jwt_required()
def save_user_data():
    try:
        user_id = int(get_jwt_identity())
        print(f"DEBUG: Saving data for user_id: {user_id}")  # Debug line
        
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401
            
        data = request.get_json()
        print(f"DEBUG: Received data: {data}")  # Debug line
        
        course_data = data.get('course_data', {})
        target_cgpa = data.get('target_cgpa')

        # Find or create user data record
        user_data = UserData.query.filter_by(user_id=user_id).first()
        
        if not user_data:
            user_data = UserData(user_id=user_id)
            db.session.add(user_data)
            print(f"DEBUG: Created new UserData record for user_id: {user_id}")  # Debug line

        # Update data
        user_data.course_data = json.dumps(course_data)
        user_data.target_cgpa = target_cgpa
        user_data.updated_at = datetime.now(timezone.utc)

        # Calculate and save CGPA history
        stats = calculate_stats(course_data)
        if stats['cgpa'] > 0:
            cgpa_history = CGPAHistory(
                user_id=user_id,
                cgpa=stats['cgpa'],
                total_credits=stats['totalCredits'],
                grade_points=stats['totalPoints']
            )
            db.session.add(cgpa_history)

        db.session.commit()
        print(f"DEBUG: Data saved successfully for user_id: {user_id}")  # Debug line

        return jsonify({
            'message': 'Data saved successfully',
            'stats': stats
        })

    except Exception as e:
        print(f"DEBUG: Error in save_user_data: {str(e)}")  # Debug line
        db.session.rollback()
        return jsonify({'message': 'Failed to save data', 'error': str(e)}), 500

@app.route('/api/user/cgpa-history', methods=['GET'])
@jwt_required()
def get_cgpa_history():
    try:
        user_id = int(get_jwt_identity())
        history = CGPAHistory.query.filter_by(user_id=user_id).order_by(CGPAHistory.recorded_at).all()
        
        history_data = []
        for record in history:
            history_data.append({
                'cgpa': record.cgpa,
                'total_credits': record.total_credits,
                'grade_points': record.grade_points,
                'recorded_at': record.recorded_at.isoformat()
            })
        
        return jsonify({'history': history_data})
    
    except Exception as e:
        return jsonify({'message': 'Failed to fetch CGPA history', 'error': str(e)}), 500

@app.route('/api/courses', methods=['GET'])
def get_courses():
    """Get all available courses with their names and credits, grouped by section"""
    
    # Define course groups
    course_groups = {
        'foundation': [],
        'programming': [],
        'dataScience_core': [],
        'dataScience_option1': [],
        'dataScience_option2': []
    }
    
    # Option 1 courses (Business Analytics Path)
    option1_courses = {'BSMS2002', 'BSMS2001P'}
    
    # Option 2 courses (Generative AI Path)  
    option2_courses = {'BSDA2001', 'BSDA2001P'}
    
    # Core Data Science courses (always available)
    core_ds_courses = {'BSCS2004', 'BSMS2001', 'BSCS2007', 'BSCS2008', 'BSCS2008P', 'BSSE2002'}
    
    for course_id, course_name in COURSE_NAMES.items():
        credits = get_credits_for_course(course_id)
        course_obj = {
            'id': course_id,
            'name': course_name,
            'credits': credits
        }
        
        if course_id.startswith('foundation'):
            course_groups['foundation'].append(course_obj)
        elif course_id.startswith('programming'):
            course_groups['programming'].append(course_obj)
        elif course_id in core_ds_courses:
            course_groups['dataScience_core'].append(course_obj)
        elif course_id in option1_courses:
            course_groups['dataScience_option1'].append(course_obj)
        elif course_id in option2_courses:
            course_groups['dataScience_option2'].append(course_obj)
    
    return jsonify({
        'courses': course_groups,
        'options': {
            'dataScience': {
                'option1': {
                    'name': 'Business Analytics Path',
                    'description': 'Business Analytics + Business Data Management Project',
                    'courses': ['BSMS2002', 'BSMS2001P']
                },
                'option2': {
                    'name': 'Generative AI Path', 
                    'description': 'Introduction to Deep Learning and Generative AI + Project',
                    'courses': ['BSDA2001', 'BSDA2001P']
                }
            }
        }
    })

@app.route('/api/admin/users', methods=['GET'])
def list_users():
    """Debug endpoint to list all users (remove in production)"""
    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
        return jsonify({'users': user_list, 'count': len(user_list)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin functionality
def create_admin_user():
    """Create admin user if it doesn't exist"""
    try:
        # First check if the table exists (critical for serverless)
        if not db.engine.dialect.has_table(db.engine, 'user'):
            print("Users table doesn't exist yet when creating admin, creating tables...")
            db.create_all()
            print("Tables created in admin user creation")
        
        # Now try to create the admin user
        try:
            admin = User.query.filter_by(username='admin').first()
        except Exception as query_error:
            print(f"Error querying for admin user: {query_error}")
            admin = None  # Assume admin doesn't exist if there's an error
        
        if not admin:
            print("Creating admin user...")
            password_hash = bcrypt.generate_password_hash('4129').decode('utf-8')
            admin = User(
                username='admin',
                email='admin@cgpatracker.com',
                password_hash=password_hash,
                is_admin=True
            )
            try:
                db.session.add(admin)
                db.session.commit()
                print("Admin user created successfully!")
            except Exception as commit_error:
                print(f"Error committing admin user: {commit_error}")
                db.session.rollback()
        else:
            print("Admin user already exists")
    except Exception as e:
        print(f"Error creating admin user: {e}")

def admin_required(f):
    """Decorator to require admin privileges"""
    from functools import wraps
    from flask import request
    
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        print(f"Admin check for user ID: {current_user_id}")
        
        # First check if we have a valid user in the database
        user = User.query.get(current_user_id)
        
        # If no user found but we're in serverless, attempt to create/find admin
        if not user and os.environ.get('VERCEL_REGION'):
            print("User not found in database but in serverless environment")
            # This could happen if the database was reset or initialized after token was issued
            # Try to create or get admin user as fallback
            try:
                # Check for admin token fallback mechanism
                auth_header = request.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    print("Found Authorization header, checking for admin")
                    # Get admin user (create if not exists)
                    admin_user = User.query.filter_by(username='admin').first()
                    if not admin_user:
                        print("Creating admin user for authentication")
                        password_hash = bcrypt.generate_password_hash('4129').decode('utf-8')
                        admin_user = User(
                            username='admin', 
                            email='admin@cgpatracker.com',
                            password_hash=password_hash,
                            is_admin=True
                        )
                        db.session.add(admin_user)
                        db.session.commit()
                    
                    # For security reasons, validate the endpoint path for backup specifically
                    if request.path == '/api/admin/backup':
                        print("Allowing admin backup endpoint access")
                        return f(*args, **kwargs)
            except Exception as e:
                print(f"Error in admin fallback: {e}")
        
        if not user:
            print(f"User ID {current_user_id} not found in database")
            return jsonify({'message': 'User not found'}), 403
            
        if not user.is_admin:
            print(f"User {user.username} is not an admin")
            return jsonify({'message': 'Admin privileges required'}), 403
            
        print(f"Admin access granted for {user.username}")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/admin/backup', methods=['GET'])
@admin_required
def backup_database():
    """Download database backup - Works in both local and serverless environments"""
    try:
        # Log information about the request
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        print(f"Backup requested by user ID: {current_user_id}, Username: {user.username if user else 'Unknown'}, Admin: {user.is_admin if user else False}")
        
        # Check if we're in serverless environment
        is_serverless = os.environ.get('VERCEL_REGION') is not None
        
        if is_serverless:
            # In serverless, create a temporary in-memory DB file
            try:
                import sqlite3
                import tempfile
                import io
                
                # Create a temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                temp_path = temp_file.name
                temp_file.close()
                
                print(f"Created temporary file at: {temp_path}")
                
                # Create a new SQLite database
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                
                # Create tables
                cursor.execute('''
                CREATE TABLE user (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP,
                    last_login TIMESTAMP,
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
                    updated_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user (id)
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE cgpa_history (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    cgpa REAL,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user (id)
                )
                ''')
                
                # Copy data from the in-memory database to the file
                # Users
                for user in User.query.all():
                    cursor.execute(
                        "INSERT INTO user (id, username, email, password_hash, created_at, last_login, is_active, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            user.id,
                            user.username,
                            user.email,
                            user.password_hash,
                            user.created_at.isoformat() if user.created_at else None,
                            user.last_login.isoformat() if user.last_login else None,
                            1 if user.is_active else 0,
                            1 if user.is_admin else 0
                        )
                    )
                
                # User Data
                for data in UserData.query.all():
                    cursor.execute(
                        "INSERT INTO user_data (id, user_id, course_data, target_cgpa, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            data.id,
                            data.user_id,
                            data.course_data,
                            data.target_cgpa,
                            data.updated_at.isoformat() if data.updated_at else None
                        )
                    )
                
                # CGPA History
                for history in CGPAHistory.query.all():
                    cursor.execute(
                        "INSERT INTO cgpa_history (id, user_id, cgpa, timestamp) VALUES (?, ?, ?, ?)",
                        (
                            history.id,
                            history.user_id,
                            history.cgpa,
                            history.timestamp.isoformat() if history.timestamp else None
                        )
                    )
                
                # Commit changes and close
                conn.commit()
                conn.close()
                
                print("Database backup created successfully")
                
                # Generate timestamp for filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_filename = f"cgpa_tracker_backup_{timestamp}.db"
                
                # Read the file into memory
                with open(temp_path, 'rb') as f:
                    file_data = f.read()
                
                # Delete the temporary file
                os.unlink(temp_path)
                
                # Return file as download
                response = Response(
                    file_data,
                    mimetype='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename={backup_filename}'}
                )
                return response
                
            except Exception as export_error:
                print(f"Error creating database backup: {export_error}")
                import traceback
                traceback.print_exc()
                return jsonify({
                    'message': 'Error creating database backup',
                    'error': str(export_error)
                }), 500
        else:
            # In local environment, use SQLite backup
            # Create backup directory if it doesn't exist
            backup_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"cgpa_tracker_backup_{timestamp}.db"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Get database path from config
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            if db_uri.startswith('sqlite:///'):
                db_path = db_uri[10:]  # Remove sqlite:///
                if not os.path.isabs(db_path):
                    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
                    
                # Copy database file
                shutil.copy2(db_path, backup_path)
                
                # Return the file for download
                return send_file(
                    backup_path,
                    as_attachment=True,
                    download_name=backup_filename,
                    mimetype='application/octet-stream'
                )
            else:
                return jsonify({'message': 'Backup only supports SQLite databases'}), 400
    except Exception as e:
        print(f"Backup error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/restore', methods=['POST'])
@admin_required
def restore_database():
    """Restore database from uploaded file - Supports JSON restore in serverless"""
    try:
        # Check if we're in serverless environment
        is_serverless = os.environ.get('VERCEL_REGION') is not None
        
        if is_serverless:
            # For serverless, handle both .db and .json files
            if 'file' not in request.files:
                return jsonify({'message': 'No file part in the request'}), 400
                
            file = request.files['file']
            if file.filename == '':
                return jsonify({'message': 'No file selected'}), 400
                
            is_db_file = file.filename.endswith('.db')
            is_json_file = file.filename.endswith('.json')
            
            if not (is_db_file or is_json_file):
                return jsonify({'message': 'Only .db or .json backup files are supported'}), 400
                
            try:
                import json
                import tempfile
                import sqlite3
                
                if is_json_file:
                    # Read JSON data
                    backup_data = json.loads(file.read().decode('utf-8'))
                    
                    # Validate backup format
                    if 'users' not in backup_data:
                        return jsonify({'message': 'Invalid JSON backup format'}), 400
                    
                elif is_db_file:
                    # Handle SQLite DB file
                    try:
                        # Create a temporary file to store the uploaded database
                        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                        file.save(temp_file.name)
                        temp_file.close()
                        
                        # Try to connect to the uploaded database
                        conn = sqlite3.connect(temp_file.name)
                        cursor = conn.cursor()
                        
                        # Check if it has the required tables
                        tables_query = "SELECT name FROM sqlite_master WHERE type='table';"
                        cursor.execute(tables_query)
                        tables = [row[0] for row in cursor.fetchall()]
                        
                        required_tables = ['user', 'user_data', 'cgpa_history']
                        for table in required_tables:
                            if table.lower() not in [t.lower() for t in tables]:
                                os.unlink(temp_file.name)
                                return jsonify({'message': f'Invalid database backup: missing {table} table'}), 400
                        
                        # Create a JSON-like structure from the SQLite data
                        backup_data = {'users': []}
                        
                        # Get users
                        cursor.execute("SELECT id, username, email, password_hash, created_at, last_login, is_active, is_admin FROM user")
                        users = cursor.fetchall()
                        
                        for user in users:
                            user_id, username, email, password_hash, created_at, last_login, is_active, is_admin = user
                            user_data = {
                                'id': user_id,
                                'username': username,
                                'email': email,
                                'password_hash': password_hash,
                                'created_at': created_at,
                                'last_login': last_login,
                                'is_active': bool(is_active),
                                'is_admin': bool(is_admin),
                                'data': [],
                                'cgpa_history': []
                            }
                            
                            # Get user data
                            cursor.execute("SELECT id, semester, credits, gpa, notes, created_at FROM user_data WHERE user_id = ?", (user_id,))
                            data_items = cursor.fetchall()
                            
                            for data in data_items:
                                d_id, semester, credits, gpa, notes, d_created_at = data
                                user_data['data'].append({
                                    'id': d_id,
                                    'semester': semester,
                                    'credits': credits,
                                    'gpa': gpa,
                                    'notes': notes,
                                    'created_at': d_created_at
                                })
                            
                            # Get CGPA history
                            cursor.execute("SELECT id, cgpa, timestamp FROM cgpa_history WHERE user_id = ?", (user_id,))
                            history_items = cursor.fetchall()
                            
                            for history in history_items:
                                h_id, cgpa, timestamp = history
                                user_data['cgpa_history'].append({
                                    'id': h_id,
                                    'cgpa': cgpa,
                                    'timestamp': timestamp
                                })
                            
                            backup_data['users'].append(user_data)
                        
                        # Close connection and remove temp file
                        conn.close()
                        os.unlink(temp_file.name)
                        
                    except sqlite3.Error as sql_error:
                        if os.path.exists(temp_file.name):
                            os.unlink(temp_file.name)
                        return jsonify({'message': f'Invalid SQLite database file: {str(sql_error)}'}), 400
                    except Exception as db_error:
                        if os.path.exists(temp_file.name):
                            os.unlink(temp_file.name)
                        return jsonify({'message': f'Error processing database file: {str(db_error)}'}), 500
                    
                # Clear existing data
                try:
                    UserData.query.delete()
                    CGPAHistory.query.delete()
                    User.query.filter(User.username != 'admin').delete()
                    db.session.commit()
                    print("Existing data cleared")
                except Exception as clear_error:
                    print(f"Error clearing data: {clear_error}")
                    db.session.rollback()
                    return jsonify({'message': f'Error clearing existing data: {str(clear_error)}'}), 500
                
                # Import users
                admin_user = User.query.filter_by(username='admin').first()
                admin_id = admin_user.id if admin_user else None
                
                users_created = 0
                for user_data in backup_data['users']:
                    # Skip admin user
                    if user_data.get('username') == 'admin':
                        continue
                        
                    # Create user
                    try:
                        new_user = User(
                            username=user_data.get('username'),
                            email=user_data.get('email'),
                            password_hash=user_data.get('password_hash', bcrypt.generate_password_hash('changeme').decode('utf-8')),
                            is_active=user_data.get('is_active', True),
                            is_admin=user_data.get('is_admin', False)
                        )
                        if 'created_at' in user_data and user_data['created_at']:
                            new_user.created_at = datetime.fromisoformat(user_data['created_at'])
                        if 'last_login' in user_data and user_data['last_login']:
                            new_user.last_login = datetime.fromisoformat(user_data['last_login'])
                            
                        db.session.add(new_user)
                        db.session.flush()  # Get the ID without committing
                        
                        # Import user data
                        if 'data' in user_data:
                            for data_item in user_data['data']:
                                new_data = UserData(
                                    user_id=new_user.id,
                                    semester=data_item.get('semester'),
                                    credits=data_item.get('credits'),
                                    gpa=data_item.get('gpa'),
                                    notes=data_item.get('notes')
                                )
                                if 'created_at' in data_item and data_item['created_at']:
                                    new_data.created_at = datetime.fromisoformat(data_item['created_at'])
                                db.session.add(new_data)
                                
                        # Import CGPA history
                        if 'cgpa_history' in user_data:
                            for history_item in user_data['cgpa_history']:
                                new_history = CGPAHistory(
                                    user_id=new_user.id,
                                    cgpa=history_item.get('cgpa')
                                )
                                if 'timestamp' in history_item and history_item['timestamp']:
                                    new_history.timestamp = datetime.fromisoformat(history_item['timestamp'])
                                db.session.add(new_history)
                                
                        users_created += 1
                    except Exception as user_error:
                        print(f"Error importing user {user_data.get('username')}: {user_error}")
                        # Continue with other users
                        
                # Commit all changes
                db.session.commit()
                return jsonify({
                    'message': 'Database restored successfully',
                    'users_imported': users_created
                })
                
            except json.JSONDecodeError:
                return jsonify({'message': 'Invalid JSON format'}), 400
            except Exception as import_error:
                print(f"Error importing data: {import_error}")
                import traceback
                traceback.print_exc()
                db.session.rollback()
                return jsonify({'message': f'Error importing data: {str(import_error)}'}), 500
        else:
            # For local environment, use SQLite restore
            if 'file' not in request.files:
                return jsonify({'message': 'No file part in the request'}), 400
                
            file = request.files['file']
            if file.filename == '':
                return jsonify({'message': 'No file selected'}), 400
                
            if not file.filename.endswith('.db'):
                return jsonify({'message': 'Only .db backup files are supported'}), 400
                
            try:
                # Create a temporary file to store the uploaded database
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                file.save(temp_file.name)
                temp_file.close()
                
                # Get the path to the current database
                db_uri = app.config['SQLALCHEMY_DATABASE_URI']
                if db_uri.startswith('sqlite:///'):
                    db_path = db_uri[10:]  # Remove sqlite:///
                    if not os.path.isabs(db_path):
                        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
                        
                    # Create a backup before overwriting
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    backup_filename = f"cgpa_tracker_backup_before_restore_{timestamp}.db"
                    backup_dir = os.path.join(os.path.dirname(db_path))
                    backup_path = os.path.join(backup_dir, backup_filename)
                    
                    # Make backup directory if it doesn't exist
                    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                    
                    # Create backup
                    shutil.copy2(db_path, backup_path)
                    
                    # Close database connection
                    db.session.close()
                    db.engine.dispose()
                    
                    # Replace current database with uploaded one
                    shutil.copy2(temp_file.name, db_path)
                    
                    # Remove temp file
                    os.unlink(temp_file.name)
                    
                    return jsonify({
                        'message': 'Database restored successfully',
                        'backup_created': backup_filename
                    })
                else:
                    return jsonify({'message': 'Restore only supports SQLite databases'}), 400
                    
            except Exception as restore_error:
                print(f"Restore error: {restore_error}")
                import traceback
                traceback.print_exc()
                return jsonify({'message': f'Error restoring database: {str(restore_error)}'}), 500
    except Exception as e:
        print(f"Restore error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    """Admin endpoint to list all users with detailed info"""
    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_data = UserData.query.filter_by(user_id=user.id).first()
            course_count = 0
            if user_data and user_data.course_data:
                course_data = json.loads(user_data.course_data)
                course_count = len(course_data.get('courses', {}))
            
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'course_count': course_count,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
        return jsonify({'users': user_list, 'count': len(user_list)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    """Get admin dashboard statistics"""
    try:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(is_admin=True).count()
        
        # Get users with course data
        users_with_data = db.session.query(User).join(UserData).count()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'admin_users': admin_users,
            'users_with_data': users_with_data,
            'database_size': 'N/A (Serverless environment)'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize database and admin user
def init_db():
    """Initialize database and create admin user"""
    try:
        # First check if we can connect to the database
        connection = db.engine.connect()
        connection.close()
        print("Database connection successful")
        
        # Now create tables
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as table_error:
            print(f"Error creating tables: {table_error}")
        
        # Now create admin user
        create_admin_user()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize on import for Vercel - always initialize for serverless environment
with app.app_context():
    try:
        print("Starting database initialization for serverless environment...")
        # Force initialization for serverless - tables need to be created each time
        init_db()
        print("Database initialization completed for serverless")
    except Exception as e:
        print(f"Database initialization error (non-critical): {e}")

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'message': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'message': 'Authorization token is required'}), 401

# This is the application object that Vercel will import
application = app

# Health check endpoint - useful for debugging API status
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Check database connection by executing simple query
        try:
            db.session.execute('SELECT 1').fetchall()
            db_status = "connected"
        except Exception as db_error:
            db_status = f"error: {str(db_error)}"
        
        # Return health information
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'environment': 'vercel' if os.environ.get('VERCEL_REGION') else 'local',
            'database': db_status,
            'database_uri_type': 'in-memory' if ':memory:' in app.config['SQLALCHEMY_DATABASE_URI'] else 'file-based',
            'endpoints': {
                'register': '/api/auth/register',
                'login': '/api/auth/login',
                'health': '/api/health'
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

# Required handler for Vercel serverless
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # If this is an API request that wasn't matched, return 404
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
        
    # Otherwise serve the index.html file
    return app.send_static_file('index.html') if os.path.exists(os.path.join(app.static_folder, 'index.html')) else render_template('index.html')

# For local development
if __name__ == '__main__':
    app.run(debug=True)
