# CGPA Tracker App - IIT Madras BS Program

A web application for tracking CGPA for IIT Madras Bachelor of Science program students. Features user authentication, course grade management, and real-time CGPA calculations.

## Features

- **User Authentication**: Secure login/registration system with JWT tokens
- **CGPA Calculation**: Real-time CGPA calculation based on IIT Madras BS credit structure
- **Course Management**: Track grades for Foundation, Programming, and Data Science courses
- **Dashboard**: Visual representation of academic progress with charts
- **Grade Distribution**: Pie chart showing distribution of grades
- **CGPA History**: Line chart tracking CGPA changes over time
- **Progress Tracking**: Visual progress toward degree completion

## Course Structure

### Foundation Level (32 Credits)
- Mathematics for Data Science I & II
- Statistics for Data Science I & II
- Computational Thinking & Programming in Python
- English I & II

### Programming Diploma (27 Credits)
- Database Management Systems
- Programming, Data Structures and Algorithms
- Modern Application Development I & II (with projects)
- Programming Concepts using Java
- System Commands

### Data Science Diploma (28 Credits)
- Introduction to Data Science
- Business Data Management & Analytics
- Machine Learning (Foundations, Techniques, Practice)
- Tools in Data Science

## Installation

1. **Clone or download the project files**

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Open your browser and go to**:
   ```
   http://localhost:5000
   ```

## Usage

1. **Register**: Create a new account with username and password
2. **Login**: Use your credentials to access the dashboard
3. **Add Grades**: Select courses and enter your grades (S, A, B, C, D, E)
4. **View Progress**: Monitor your CGPA, credits, and academic progress
5. **Save Changes**: Click "Save Changes" to persist your data

## Grade Point System

- **S**: 10 points (Outstanding)
- **A**: 9 points (Excellent)
- **B**: 8 points (Very Good)
- **C**: 7 points (Good)
- **D**: 6 points (Average)
- **E**: 4 points (Pass)

## CGPA Formula

```
CGPA = Σ(Grade Points × Credits) / Σ(Credits)
```

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Charts**: Chart.js
- **Security**: bcrypt for password hashing

## Database Schema

The application uses SQLite with three main tables:
- **users**: User authentication data
- **user_data**: Course grades and target CGPA
- **cgpa_history**: Historical CGPA records

## File Structure

```
cgpa-tracker/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/
│   ├── index.html     # Login/Registration page
│   └── dashboard.html # Main dashboard
└── README.md          # This file
```

## Development

The application runs in debug mode by default. For production deployment:

1. Set `JWT_SECRET_KEY` environment variable
2. Configure a production database
3. Set `debug=False` in `app.run()`
4. Use a production WSGI server like Gunicorn

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- SQL injection protection via SQLAlchemy ORM
- CORS protection
- Input validation and sanitization

## Browser Support

- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge

## License

This project is created for educational purposes for IIT Madras BS program students.
---
Copy-Item "last.db" -Destination ".\instance\cgpa_tracker.db" -Force