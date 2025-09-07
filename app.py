from flask import Flask, request, jsonify, render_template, send_file
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

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cgpa_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_ALGORITHM'] = 'HS256'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

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
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        print(f"DEBUG REGISTER: Attempting registration for: {username}, {email}")

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Check if user already exists
        existing_user = None
        if email:
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
        else:
            existing_user = User.query.filter(User.username == username).first()

        if existing_user:
            if existing_user.username == username:
                return jsonify({'message': 'Username already exists. Please choose a different username.'}), 409
            else:
                return jsonify({'message': 'Email already exists. Please use a different email.'}), 409

        # Create new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        print(f"DEBUG REGISTER: User created successfully: {username}")
        return jsonify({'message': 'User created successfully'}), 201

    except Exception as e:
        print(f"DEBUG REGISTER ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username_or_email = data.get('username')
        password = data.get('password')

        print(f"DEBUG LOGIN: Attempting login for: {username_or_email}")

        if not username_or_email or not password:
            return jsonify({'message': 'Username/email and password are required'}), 400

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
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            password_hash = bcrypt.generate_password_hash('4129').decode('utf-8')
            admin = User(
                username='admin',
                email='admin@cgpatracker.com',
                password_hash=password_hash,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists")
    except Exception as e:
        print(f"Error creating admin user: {e}")

def admin_required(f):
    """Decorator to require admin privileges"""
    from functools import wraps
    
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or not user.is_admin:
            return jsonify({'message': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/admin/backup', methods=['GET'])
@admin_required
def backup_database():
    """Download database backup"""
    try:
        # Check multiple possible database locations
        possible_paths = [
            os.path.join(app.instance_path, 'cgpa_tracker.db'),  # Instance folder
            os.path.join(os.getcwd(), 'cgpa_tracker.db'),        # Current directory
            os.path.join(os.getcwd(), 'instance', 'cgpa_tracker.db')  # Instance subfolder
        ]
        
        db_path = None
        for path in possible_paths:
            if os.path.exists(path):
                db_path = path
                break
        
        if not db_path:
            return jsonify({'error': 'Database file not found'}), 404
        
        return send_file(
            db_path,
            as_attachment=True,
            download_name=f'cgpa_tracker_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db',
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/restore', methods=['POST'])
@admin_required
def restore_database():
    """Restore database from uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.db'):
            return jsonify({'error': 'Invalid file type. Only .db files are allowed'}), 400
        
        # Find current database location
        possible_paths = [
            os.path.join(app.instance_path, 'cgpa_tracker.db'),  # Instance folder
            os.path.join(os.getcwd(), 'cgpa_tracker.db'),        # Current directory
            os.path.join(os.getcwd(), 'instance', 'cgpa_tracker.db')  # Instance subfolder
        ]
        
        current_db = None
        for path in possible_paths:
            if os.path.exists(path):
                current_db = path
                break
        
        # If no database exists, use the instance path
        if not current_db:
            # Ensure instance directory exists
            os.makedirs(app.instance_path, exist_ok=True)
            current_db = os.path.join(app.instance_path, 'cgpa_tracker.db')
        
        # Create backup of current database
        backup_name = f'cgpa_tracker_backup_before_restore_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        backup_path = os.path.join(os.path.dirname(current_db), backup_name)
        
        if os.path.exists(current_db):
            shutil.copy2(current_db, backup_path)
        
        # Save uploaded file as new database
        file.save(current_db)
        
        # Reinitialize database connection
        db.engine.dispose()
        
        # Get file size for confirmation
        file_size = os.path.getsize(current_db)
        
        return jsonify({
            'success': True,
            'message': 'Database restored successfully! The system has been updated with the new data.',
            'details': {
                'restored_file': file.filename,
                'database_size': f"{file_size / 1024:.2f} KB",
                'backup_created': backup_name,
                'restore_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })
        
    except Exception as e:
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
            'database_size': os.path.getsize(os.path.join(os.getcwd(), 'cgpa_tracker.db')) if os.path.exists('cgpa_tracker.db') else 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create tables and admin user
with app.app_context():
    db.create_all()
    create_admin_user()

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

if __name__ == '__main__':
    app.run(debug=True)
