#!/usr/bin/env python3
"""
Test script for CGPA Tracker application
Verifies that all dependencies are installed correctly
"""

import sys
import importlib

def test_imports():
    """Test if all required packages can be imported"""
    required_packages = [
        'flask',
        'flask_sqlalchemy',
        'flask_jwt_extended',
        'flask_bcrypt',
        'flask_cors',
        'werkzeug'
    ]
    
    print("Testing package imports...")
    print("=" * 40)
    
    failed_imports = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"✓ {package}")
        except ImportError as e:
            print(f"✗ {package} - {e}")
            failed_imports.append(package)
    
    print("=" * 40)
    
    if failed_imports:
        print(f"\n❌ Failed to import {len(failed_imports)} packages:")
        for package in failed_imports:
            print(f"   - {package}")
        print("\nPlease install missing packages using:")
        print("   pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All packages imported successfully!")
        return True

def test_database_models():
    """Test if database models can be created"""
    try:
        from app import app, db, User, UserData, CGPAHistory
        
        print("\nTesting database models...")
        print("=" * 40)
        
        with app.app_context():
            # Try to create tables
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Test model creation
            test_user = User(username="test", email="test@example.com", password_hash="test")
            print("✓ User model created successfully")
            
            test_data = UserData(user_id=1, course_data="{}", target_cgpa=8.0)
            print("✓ UserData model created successfully")
            
            test_history = CGPAHistory(user_id=1, cgpa=8.0, total_credits=32, grade_points=256.0)
            print("✓ CGPAHistory model created successfully")
            
        print("=" * 40)
        print("✅ Database models test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Database models test failed: {e}")
        return False

def test_grade_calculations():
    """Test CGPA calculation functions"""
    try:
        from app import calculate_stats, get_credits_for_course, GRADE_POINTS
        
        print("\nTesting CGPA calculations...")
        print("=" * 40)
        
        # Test credit calculation
        assert get_credits_for_course('foundation-1') == 4
        assert get_credits_for_course('programming-4') == 2  # Project course
        assert get_credits_for_course('programming-8') == 3  # System Commands
        print("✓ Credit calculation working correctly")
        
        # Test CGPA calculation
        test_course_data = {
            'courses': {
                'foundation-1': {'grade': 'A', 'courseName': 'Math for DS I'},
                'foundation-2': {'grade': 'S', 'courseName': 'Stats for DS I'},
                'programming-1': {'grade': 'B', 'courseName': 'DBMS'}
            }
        }
        
        stats = calculate_stats(test_course_data)
        expected_cgpa = (9*4 + 10*4 + 8*4) / (4+4+4)  # Should be 9.0
        
        assert abs(stats['cgpa'] - 9.0) < 0.01
        assert stats['totalCredits'] == 12
        assert stats['completedCourses'] == 3
        print("✓ CGPA calculation working correctly")
        
        print("=" * 40)
        print("✅ Grade calculations test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Grade calculations test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("CGPA Tracker - Installation Test")
    print("=" * 50)
    print()
    
    tests = [
        test_imports,
        test_database_models,
        test_grade_calculations
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is ready to run.")
        print("\nTo start the application, run:")
        print("   python app.py")
        print("\nOr use the run scripts:")
        print("   run.bat (Windows)")
        print("   run.ps1 (PowerShell)")
    else:
        print("❌ Some tests failed. Please check the installation.")
        sys.exit(1)

if __name__ == "__main__":
    main()
