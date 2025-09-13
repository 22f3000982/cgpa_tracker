from flask import Flask, request, jsonify, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
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

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)

# Models
class UserData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_data = db.Column(db.Text)  # JSON string
    target_cgpa = db.Column(db.Float)
    updated_at = db.Column(db.String(50), default=lambda: datetime.now(timezone.utc).isoformat())

class CGPAHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cgpa = db.Column(db.Float, nullable=False)
    total_credits = db.Column(db.Integer, nullable=False)
    grade_points = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.String(50), default=lambda: datetime.now(timezone.utc).isoformat())

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
    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/user/data', methods=['GET'])
def get_user_data():
    try:
        # Since there's no authentication, we'll use a single user data record
        user_data = UserData.query.first()

        if not user_data:
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
        print(f"DEBUG: Error in get_user_data: {str(e)}")
        return jsonify({'message': 'Failed to fetch user data', 'error': str(e)}), 500

@app.route('/api/user/data', methods=['POST'])
def save_user_data():
    try:
        data = request.get_json()
        print(f"DEBUG: Received data: {data}")
        
        course_data = data.get('course_data', {})
        target_cgpa = data.get('target_cgpa')

        # Find or create user data record (single record for all users)
        user_data = UserData.query.first()
        
        if not user_data:
            user_data = UserData()
            db.session.add(user_data)
            print(f"DEBUG: Created new UserData record")

        # Update data
        user_data.course_data = json.dumps(course_data)
        user_data.target_cgpa = target_cgpa
        user_data.updated_at = datetime.now(timezone.utc).isoformat()

        # Calculate and save CGPA history
        stats = calculate_stats(course_data)
        if stats['cgpa'] > 0:
            cgpa_history = CGPAHistory(
                cgpa=stats['cgpa'],
                total_credits=stats['totalCredits'],
                grade_points=stats['totalPoints']
            )
            db.session.add(cgpa_history)

        db.session.commit()
        print(f"DEBUG: Data saved successfully")

        return jsonify({
            'message': 'Data saved successfully',
            'stats': stats
        })

    except Exception as e:
        print(f"DEBUG: Error in save_user_data: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Failed to save data', 'error': str(e)}), 500

@app.route('/api/user/cgpa-history', methods=['GET'])
def get_cgpa_history():
    try:
        history = CGPAHistory.query.order_by(CGPAHistory.recorded_at).all()
        
        history_data = []
        for record in history:
            history_data.append({
                'cgpa': record.cgpa,
                'total_credits': record.total_credits,
                'grade_points': record.grade_points,
                'recorded_at': record.recorded_at
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
    
    # Debug information
    print("DEBUG: Course Groups populated:")
    for section, courses in course_groups.items():
        print(f"  {section}: {len(courses)} courses")
        
    response_data = {
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
    }
    
    print("DEBUG: Returning courses data with foundation courses count:", 
          len(response_data['courses'].get('foundation', [])))
    
    return jsonify(response_data)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
