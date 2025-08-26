from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_from_directory, send_file, abort, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy import func
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_mail import Mail, Message  
from datetime import datetime, timedelta

import json
import secrets
import io
import base64
import hmac
import hashlib
import qrcode
import csv
from io import StringIO  
import logging
import uuid
import mimetypes
import secrets
import random
import string
from datetime import datetime
import os
import time

failed_attempts = {}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jriit_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ANNOUNCEMENT_UPLOAD_FOLDER'] = 'static/uploads/announcements'
os.makedirs(app.config['ANNOUNCEMENT_UPLOAD_FOLDER'], exist_ok=True)
app.config['UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  
app.config['QR_EXPIRY_MINUTES'] = 15  # Default QR expiry
app.config['ATTENDANCE_GRACE_PERIOD'] = 10  # Grace period in minutes
app.config['MAX_DISTANCE_METERS'] = 100  # Default geo-fence radius
app.config['ENABLE_GEO_FENCING'] = True  # Enable/disable geo-fencing
app.config['ENABLE_DEVICE_TRACKING'] = True  # disable device tracking
app.config['QR_SECRET_LENGTH'] = 32  
app.config['BACKUP_PIN_LENGTH'] = 6 
app.config['RATE_LIMIT_PER_MINUTE'] = 60

# Flask-Mail configuration (update these with your SMTP server details)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  
app.config['MAIL_PASSWORD'] = 'your_email_password'   
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'  

mail = Mail(app) 

socketio = SocketIO(app, cors_allowed_origins="*")

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'teacher', 'academic', 'student'
    first_login = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(200), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1-6
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='student_profile', foreign_keys=[user_id])

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    
    user = db.relationship('User', backref='teacher_profile', foreign_keys=[user_id])

class Academic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    
    user = db.relationship('User', backref='academic_profile', foreign_keys=[user_id])

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_code = db.Column(db.String(20), unique=True, nullable=False)
    subject_name = db.Column(db.String(100), nullable=False)
    semester = db.Column(db.Integer, nullable=False)  # 1-6
    course = db.Column(db.String(50), nullable=False)
    credits = db.Column(db.Integer, default=3)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    teacher = db.relationship('Teacher', backref='subjects')

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    is_final = db.Column(db.Boolean, default=False)  # Once approved
    
    student = db.relationship('Student', backref='results')
    subject = db.relationship('Subject', backref='results')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    activity = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    ip_address = db.Column(db.String(45), nullable=True)
    
    user = db.relationship('User', backref='activity_logs')


class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # lecture, exam, holiday, practical, assessment
    color = db.Column(db.String(7), default='#007bff')  # Hex color code
    
    # Targeting
    target_type = db.Column(db.String(20), nullable=False)  # all, course, department, semester
    target_value = db.Column(db.String(50), nullable=True)  # specific course/department/semester
    
    # Creator info
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Reminder settings
    reminder_enabled = db.Column(db.Boolean, default=True)
    reminder_time = db.Column(db.Integer, default=30)  # minutes before event
    
    creator = db.relationship('User', backref='calendar_events')

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    
    # Targeting
    target_type = db.Column(db.String(20), nullable=False)  # all, course, department, semester
    target_value = db.Column(db.String(50), nullable=True)  # specific course/department/semester
    
    # Creator info
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Expiry
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # File attachments
    attachment_path = db.Column(db.String(500), nullable=True)
    attachment_name = db.Column(db.String(200), nullable=True)
    attachment_type = db.Column(db.String(50), nullable=True)  # csv, pdf, docx
    
    creator = db.relationship('User', backref='announcements')
    target_type = db.Column(db.String(20), nullable=False, index=True)
    target_value = db.Column(db.String(50), nullable=True, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)

class AnnouncementRead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey('announcement.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    announcement = db.relationship('Announcement', backref='reads')
    user = db.relationship('User', backref='announcement_reads')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # calendar, announcement, result, system
    reference_id = db.Column(db.Integer, nullable=True)  # ID of related object
    
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='notifications')

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, default=120)  # Duration in minutes
    location = db.Column(db.String(100), nullable=True)
    max_scans = db.Column(db.Integer, nullable=True)
    
    # QR Code fields
    qr_secret = db.Column(db.String(64), nullable=True)
    backup_pin = db.Column(db.String(6), nullable=True)
    qr_expiry = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Geo-fencing (optional)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    geo_radius = db.Column(db.Float, default=100)  # meters
    
    # Status tracking
    status = db.Column(db.String(20), default='scheduled')  # scheduled, active, paused, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subject = db.relationship('Subject', backref='lessons')
    teacher = db.relationship('Teacher', backref='lessons')

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    
    # Attendance details
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    scan_method = db.Column(db.String(20), default='qr')  # qr, pin, manual
    status = db.Column(db.String(20), default='present')  # present, late, absent, excused
    
    # Device and location tracking
    device_info = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    
    # Validation flags
    is_valid = db.Column(db.Boolean, default=True)
    validation_notes = db.Column(db.Text, nullable=True)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    lesson = db.relationship('Lesson', backref='attendance_records')
    student = db.relationship('Student', backref='attendance_records')

class AttendanceException(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    exception_type = db.Column(db.String(20), nullable=False)  # sick_leave, official_duty, technical_issue
    reason = db.Column(db.Text, nullable=False)
    evidence_file = db.Column(db.String(200), nullable=True)
    
    # Status
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_comments = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    lesson = db.relationship('Lesson', backref='exceptions')
    student = db.relationship('Student', backref='attendance_exceptions')
    
    
class QuestionBank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)  # mcq, true_false, fill_blank, essay, file_upload
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    difficulty_level = db.Column(db.String(10), default='medium')  # easy, medium, hard
    marks = db.Column(db.Float, default=1.0)
    
    # Question content
    question_image = db.Column(db.String(200), nullable=True)
    question_audio = db.Column(db.String(200), nullable=True)
    question_video = db.Column(db.String(200), nullable=True)
    
    # MCQ specific fields
    option_a = db.Column(db.Text, nullable=True)
    option_b = db.Column(db.Text, nullable=True)
    option_c = db.Column(db.Text, nullable=True)
    option_d = db.Column(db.Text, nullable=True)
    correct_answer = db.Column(db.String(10), nullable=True)  # For MCQ: A,B,C,D; For T/F: True/False
    
    # Essay/Fill blank answers
    model_answer = db.Column(db.Text, nullable=True)
    keywords = db.Column(db.Text, nullable=True)  # JSON array of keywords for auto-grading
    
    # Meta data
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    category = db.Column(db.String(100), nullable=True)
    
    # Relationships
    subject = db.relationship('Subject', backref='questions')
    creator = db.relationship('User', backref='created_questions')

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    
    # Timing
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # Duration in minutes
    
    # Exam configuration
    total_marks = db.Column(db.Float, default=100.0)
    passing_marks = db.Column(db.Float, default=40.0)
    max_attempts = db.Column(db.Integer, default=1)
    
    # Security settings
    randomize_questions = db.Column(db.Boolean, default=True)
    randomize_options = db.Column(db.Boolean, default=True)
    show_results_immediately = db.Column(db.Boolean, default=False)
    allow_backtrack = db.Column(db.Boolean, default=True)
    
    # Proctoring settings
    enable_proctoring = db.Column(db.Boolean, default=False)
    webcam_required = db.Column(db.Boolean, default=False)
    screen_recording = db.Column(db.Boolean, default=False)
    browser_lockdown = db.Column(db.Boolean, default=False)
    
    # Access control
    exam_password = db.Column(db.String(100), nullable=True)
    ip_restrictions = db.Column(db.Text, nullable=True)  # JSON array of allowed IPs
    
    # Targeting
    target_courses = db.Column(db.Text, nullable=True)  # JSON array
    target_semesters = db.Column(db.Text, nullable=True)  # JSON array
    specific_students = db.Column(db.Text, nullable=True)  # JSON array of student IDs
    
    # Status and meta
    status = db.Column(db.String(20), default='draft')  # draft, scheduled, active, completed, cancelled
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Auto-grading settings
    auto_grade_mcq = db.Column(db.Boolean, default=True)
    auto_grade_tf = db.Column(db.Boolean, default=True)
    auto_grade_fillblank = db.Column(db.Boolean, default=False)
    
    # Relationships
    subject = db.relationship('Subject', backref='exams')
    creator = db.relationship('User', backref='created_exams')

class ExamQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question_bank.id'), nullable=False)
    question_order = db.Column(db.Integer, nullable=False)
    marks = db.Column(db.Float, nullable=False)
    is_mandatory = db.Column(db.Boolean, default=True)
    
    # Relationships
    exam = db.relationship('Exam', backref='exam_questions')
    question = db.relationship('QuestionBank', backref='exam_questions')

class ExamAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    attempt_number = db.Column(db.Integer, default=1)
    
    # Timing
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    time_remaining = db.Column(db.Integer, nullable=True)  # Seconds remaining
    
    # Status
    status = db.Column(db.String(20), default='in_progress')  # in_progress, completed, timed_out, submitted
    
    # Security and proctoring
    browser_info = db.Column(db.Text, nullable=True)  # JSON
    ip_address = db.Column(db.String(45), nullable=True)
    violation_count = db.Column(db.Integer, default=0)
    violation_log = db.Column(db.Text, nullable=True)  # JSON array
    
    # Results
    total_score = db.Column(db.Float, default=0.0)
    percentage = db.Column(db.Float, default=0.0)
    grade = db.Column(db.String(2), nullable=True)
    result_status = db.Column(db.String(20), nullable=True)  # pass, fail, pending
    
    # Grading
    auto_graded = db.Column(db.Boolean, default=False)
    manually_graded = db.Column(db.Boolean, default=False)
    graded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    graded_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    exam = db.relationship('Exam', backref='attempts')
    student = db.relationship('Student', backref='exam_attempts')
    grader = db.relationship('User', backref='graded_attempts')

class ExamAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('exam_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question_bank.id'), nullable=False)
    
    # Answer content
    answer_text = db.Column(db.Text, nullable=True)
    selected_option = db.Column(db.String(10), nullable=True)  # A, B, C, D for MCQ
    file_upload_path = db.Column(db.String(200), nullable=True)
    
    # Scoring
    is_correct = db.Column(db.Boolean, nullable=True)
    marks_awarded = db.Column(db.Float, default=0.0)
    max_marks = db.Column(db.Float, nullable=False)
    
    # Manual grading
    manual_score = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    graded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    graded_at = db.Column(db.DateTime, nullable=True)
    
    # Time tracking
    time_spent = db.Column(db.Integer, default=0)  # Seconds spent on this question
    answered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    attempt = db.relationship('ExamAttempt', backref='answers')
    question = db.relationship('QuestionBank', backref='student_answers')

class ProctoringEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('exam_attempt.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # tab_switch, fullscreen_exit, face_not_detected, multiple_faces, suspicious_behavior
    event_data = db.Column(db.Text, nullable=True)  # JSON data
    severity = db.Column(db.String(10), default='low')  # low, medium, high, critical
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    screenshot_path = db.Column(db.String(200), nullable=True)
    
    # Relationships
    attempt = db.relationship('ExamAttempt', backref='proctoring_events')

with app.app_context():
    # db.drop_all()
    db.create_all()  
    
    if not User.query.filter_by(role='admin').first():
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        if not admin_password:
            if os.environ.get('FLASK_ENV') == 'production':
                raise ValueError("Must set ADMIN_PASSWORD environment variable in production")
            admin_password = 'admin123'  
            print("WARNING: Using default password - change in production!")

        admin_user = User(
            username=admin_username,
            password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
            role='admin',
            first_login=True  
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Created admin user '{admin_username}'")

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#CONSTANTS
COURSES = [
    'Cyber Security',
    'Tourism',
    'Information Technology (IT)',
    'Graphics Design',
    'Electronics',
    'Business Studies'
]

DEPARTMENTS = [
    'Computer Science',
    'Tourism & Hospitality',
    'Electronics Engineering',
    'Business Administration',
    'Design & Media'
]

 
# def log_activity(user_id, action, details=None, ip_address=None):
#     """Log user activity"""
#     log = ActivityLog(
#         user_id=user_id,
#         action=action,
#         details=details,
#         ip_address=ip_address,
#         activity=ActivityLog
#     )
#     db.session.add(log)
#     db.session.commit()
def log_activity(user_id, action, details=None, ip_address=None):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address,
        activity=action)
    db.session.add(log)
    db.session.commit()

def calculate_grade_and_gpa(marks):
    """Calculate grade and GPA based on marks"""
    if marks >= 90:
        return 'A+', 4.0
    elif marks >= 85:
        return 'A', 3.7
    elif marks >= 80:
        return 'A-', 3.3
    elif marks >= 75:
        return 'B+', 3.0
    elif marks >= 70:
        return 'B', 2.7
    elif marks >= 65:
        return 'B-', 2.3
    elif marks >= 60:
        return 'C+', 2.0
    elif marks >= 55:
        return 'C', 1.7
    elif marks >= 50:
        return 'C-', 1.3
    elif marks >= 45:
        return 'D+', 1.0
    elif marks >= 40:
        return 'D', 0.7
    else:
        return 'F', 0.0

def allowed_file(filename):
    """Check if uploaded file is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied: Insufficient permissions', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
    
def first_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if user and user.first_login:
            return redirect(url_for('change_credentials'))
        return f(*args, **kwargs)
    return decorated_function

def student_approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') == 'student':
            student = Student.query.filter_by(user_id=session.get('user_id')).first()
            if not student or student.status != 'approved':
                flash('Your account is pending approval. Please wait for admin approval.', 'warning')
                return redirect(url_for('pending_approval'))
        return f(*args, **kwargs)
    return decorated_function
def check_lockout(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST' and 'username' in request.form:
            username = request.form['username'].strip()
            ip = request.remote_addr
            
            # Check if IP is locked
            if ip in failed_attempts and failed_attempts[ip]['count'] >= 3:
                elapsed = time.time() - failed_attempts[ip]['timestamp']
                if elapsed < 30:  # 30 second lockout
                    remaining = int(30 - elapsed)
                    flash(f'Too many failed attempts. Please try again in {remaining} seconds.', 'error')
                    return render_template('login.html')
                else:
                    # Reset after lockout period
                    del failed_attempts[ip]
            
            # Check if user account is locked
            user = User.query.filter_by(username=username).first()
            if user and user.lock_until and user.lock_until > datetime.utcnow():
                remaining = (user.lock_until - datetime.utcnow()).seconds
                flash(f'Account temporarily locked. Please try again in {remaining} seconds.', 'error')
                return render_template('login.html')
            
        return f(*args, **kwargs)
    return decorated_function

# MAIN ROUTE
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@check_lockout
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        ip = request.remote_addr
        
        # Initialize failed attempts counter for IP
        if ip not in failed_attempts:
            failed_attempts[ip] = {'count': 0, 'timestamp': 0}
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        # Check if user account is locked
        if user and user.lock_until and user.lock_until > datetime.utcnow():
            remaining = (user.lock_until - datetime.utcnow()).seconds
            flash(f'Account temporarily locked. Please try again in {remaining} seconds.', 'error')
            return render_template('login.html')
        
        if user and check_password_hash(user.password, password):
            # Successful login - reset failed attempts
            failed_attempts[ip]['count'] = 0
            
            # Update user login info
            user.login_attempts = 0
            user.lock_until = None  # Remove any lock
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Set up session
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['login_time'] = time.time()
            
            log_activity(user.id, 'Login', f'User {username} logged in', ip)
            flash('Login successful!', 'success')
            
            if user.first_login:
                return redirect(url_for('change_credentials'))
            
            return redirect(url_for('dashboard'))
        else:
            # Failed login attempt
            failed_attempts[ip]['count'] += 1
            failed_attempts[ip]['timestamp'] = time.time()
            
            if user:
                user.login_attempts += 1
                
                # Lock account after 3 failed attempts
                if user.login_attempts >= 3:
                    user.lock_until = datetime.utcnow() + timedelta(seconds=30)
                    flash('Account temporarily locked due to too many failed attempts. Please try again in 30 seconds.', 'error')
                
                db.session.commit()
            
            if failed_attempts[ip]['count'] >= 3:
                flash('Too many failed attempts. Please wait 30 seconds before trying again.', 'error')
            else:
                attempts_left = 3 - failed_attempts[ip]['count']
                flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'error')
    
    return render_template('login.html')

# Log activity function

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    user_id = session.get('user_id')
    
    #  activity
    if user_id:
        log_activity(user_id, 'Logout', f'User {username} logged out', request.remote_addr)
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/change-credentials', methods=['GET', 'POST'])
@login_required
def change_credentials():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('change_credentials.html', user=user)
        
        if len(new_password) < 6 :
            flash('Password must be at least 6 characters long', 'error')
            return render_template('change_credentials.html', user=user)
        
        # Check if username is already taken
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already exists', 'error')
            return render_template('change_credentials.html', user=user)
        
        # Update credentials
        user.username = new_username
        user.password = generate_password_hash(new_password)
        user.first_login = False
        
        db.session.commit()
        
        # Update session
        session['username'] = new_username
        
        # Log activity
        log_activity(user.id, 'Credentials Changed', 'User changed username and password', request.remote_addr)
        
        flash('Credentials updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_credentials.html', user=user)

@app.route('/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"user_{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update user profile
        user = User.query.get(session['user_id'])
        user.profile_picture = filename
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Profile Picture Updated', 'User uploaded new profile picture', request.remote_addr)
        
        flash('Profile picture updated successfully!', 'success')
    else:
        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
@first_login_required
def profile():
    user = User.query.get(session['user_id'])
    role_profile = None
    
    if user.role == 'teacher':
        role_profile = Teacher.query.filter_by(user_id=user.id).first()
    elif user.role == 'academic':
        role_profile = Academic.query.filter_by(user_id=user.id).first()
    elif user.role == 'student':
        role_profile = Student.query.filter_by(user_id=user.id).first()
    
    return render_template('profile.html', user=user, role_profile=role_profile)

#DASHBOARD ROUTE
@app.route('/dashboard')
@login_required
@first_login_required
@student_approved_required
def dashboard():
    role = session.get('role')
    
    if role == 'admin':
        return admin_dashboard()
    elif role == 'teacher':
        return teacher_dashboard()
    elif role == 'academic':
        return academic_dashboard()
    elif role == 'student':
        return student_dashboard()
    else:
        flash('Invalid role', 'error')
        return redirect(url_for('logout'))

def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    pending_students = Student.query.filter_by(status='pending').count()
    total_teachers = Teacher.query.count()
    total_subjects = Subject.query.count()
    total_results = Result.query.count()
    
    # Recent activities
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Pending students
    pending_students_list = Student.query.filter_by(status='pending').all()
    
    # System overview
    courses_stats = {}
    for course in COURSES:
        courses_stats[course] = {
            'students': Student.query.filter_by(course=course, status='approved').count(),
            'subjects': Subject.query.filter_by(course=course).count()
        }
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         pending_students=pending_students,
                         total_teachers=total_teachers,
                         total_subjects=total_subjects,
                         total_results=total_results,
                         recent_activities=recent_activities,
                         pending_students_list=pending_students_list,
                         courses_stats=courses_stats)
@login_required
def teacher_dashboard():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    if not teacher:
        flash('Teacher profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get assigned subjects
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    # Get statistics
    total_subjects = len(subjects)
    pending_results = Result.query.filter_by(submitted_by=session['user_id'], status='pending').count()
    approved_results = Result.query.filter_by(submitted_by=session['user_id'], status='approved').count()
    
    # Get students in teacher's subjects
    students_count = db.session.query(Student).join(Result).join(Subject).filter(
        Subject.teacher_id == teacher.id,
        Student.status == 'approved'
    ).distinct().count()
    
    return render_template('teacher_dashboard.html', 
                         teacher=teacher,
                         subjects=subjects,
                         total_subjects=total_subjects,
                         pending_results=pending_results,
                         approved_results=approved_results,
                         students_count=students_count)

@app.route('/academic_dashboard')
def academic_dashboard():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    academic = Academic.query.filter_by(user_id=session['user_id']).first()
    if not academic:
        flash('Academic profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get results statistics
    pending_results = Result.query.filter_by(status='pending').count()
    approved_results = Result.query.filter_by(status='approved').count()
    rejected_results = Result.query.filter_by(status='rejected').count()
    
    
    unassigned_subjects = Subject.query.filter_by(teacher_id=None, is_active=True).count()
    
    # Get recent pending results
    recent_pending = Result.query.filter_by(status='pending')\
                                .order_by(Result.submitted_at.desc())\
                                .limit(5).all()
    
    return render_template('academic_dashboard.html',
                         academic=academic,
                         pending_results=pending_results,
                         approved_results=approved_results,
                         rejected_results=rejected_results,
                         unassigned_subjects=unassigned_subjects,
                         recent_pending=recent_pending)

@app.route('/academic_results')
def academic_results():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    academic = Academic.query.filter_by(user_id=session['user_id']).first()
    if not academic:
        flash('Academic profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get all results with pagination
    page = request.args.get('page', 1, type=int)
    results = Result.query.order_by(Result.submitted_at.desc())\
                         .paginate(page=page, per_page=10)
    
    return render_template('academic_results.html',
                         academic=academic,
                         results=results)
    

@app.route('/academic/manage-results/<int:subject_id>')
@login_required
@role_required(['academic']) 
@first_login_required
def manage_results(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    
    results = db.session.query(Result, Student)\
        .join(Student, Result.student_id == Student.id)\
        .filter(Result.subject_id == subject_id)\
        .order_by(Student.roll_number).all()
    
    return render_template('manage_results.html', 
                         subject=subject, 
                         results=results)


@app.route('/student/dashboard')
@login_required
def student_dashboard():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if not student:
        flash('Student profile not found', 'error')
        return redirect(url_for('logout'))
    
    user = User.query.get(session['user_id'])
    
    # Initialize default values
    results_by_semester = {}
    overall_gpa = None
    total_credits = 0
    total_subjects = 0
    passed_subjects = 0
    best_subject_grade = None
    
    # Get approved results only if they exist
    results = db.session.query(Result, Subject).join(Subject).filter(
        Result.student_id == student.id,
        Result.status == 'approved'
    ).order_by(Subject.semester, Subject.subject_name).all()
    
    if results:  # Only process if results exist
        for result, subject in results:
            semester = subject.semester
            if semester not in results_by_semester:
                results_by_semester[semester] = {
                    'results': [],
                    'semester_gpa': 0,
                    'semester_credits': 0
                }
            
            results_by_semester[semester]['results'].append({
                'subject': subject,
                'result': result
            })
            
            results_by_semester[semester]['semester_gpa'] += result.gpa * subject.credits
            results_by_semester[semester]['semester_credits'] += subject.credits
            total_credits += subject.credits
            total_subjects += 1
            
            if result.gpa >= 1.0:  # Considered passed
                passed_subjects += 1
                
            if not best_subject_grade or result.gpa > grade_to_value(best_subject_grade):
                best_subject_grade = result.grade
        
        # Calculate semester GPAs
        for semester in results_by_semester:
            if results_by_semester[semester]['semester_credits'] > 0:
                results_by_semester[semester]['semester_gpa'] /= results_by_semester[semester]['semester_credits']
        
        # Calculate overall GPA if we have credits
        if total_credits > 0:
            overall_gpa = sum(
                semester_data['semester_gpa'] * semester_data['semester_credits'] 
                for semester_data in results_by_semester.values()
            ) / total_credits
    
    return render_template('student_dashboard.html',
                         student=student,
                         user=user,
                         results_by_semester=results_by_semester,
                         overall_gpa=round(overall_gpa, 2) if overall_gpa is not None else None,
                         total_credits=total_credits,
                         total_subjects=total_subjects,
                         passed_subjects=passed_subjects,
                         best_subject_grade=best_subject_grade, 
                         )
    
@app.route('/pending-approval')
@login_required
def pending_approval():
    if session.get('role') != 'student':
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=session['user_id']).first()
    return render_template('pending_approval.html', student=student)

#DMIN
@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
@first_login_required
def create_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']
        full_name = request.form['full_name']
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('create_user.html', courses=COURSES, departments=DEPARTMENTS)
        
        # Create user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            created_by=session['user_id']
        )
        db.session.add(new_user)
        db.session.flush()  # Get the user ID
        
        # Create role-specific profile
        if role == 'teacher':
            department = request.form['department']
            phone = request.form.get('phone', '')
            email = request.form.get('email', '')
            teacher = Teacher(
                user_id=new_user.id,
                full_name=full_name,
                department=department,
                phone=phone,
                email=email
            )
            db.session.add(teacher)
        elif role == 'academic':
            department = request.form['department']
            academic = Academic(
                user_id=new_user.id,
                full_name=full_name,
                department=department
            )
            db.session.add(academic)
        
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'User Created', 
                    f'Created {role} account for {full_name} ({username})', 
                    request.remote_addr)
        
        flash(f'{role.title()} account created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_user.html', courses=COURSES, departments=DEPARTMENTS)

@app.route('/admin/manage-users')
@login_required
@role_required(['admin'])
@first_login_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/approve-student/<int:student_id>')
@login_required
@role_required(['admin'])
@first_login_required
def approve_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.status = 'approved'
    student.approved_by = session['user_id']
    student.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    # Log activity
    log_activity(session['user_id'], 'Student Approved', 
                f'Approved student {student.full_name} ({student.roll_number})', 
                request.remote_addr)
    
    flash('Student approved successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/reject-student/<int:student_id>')
@login_required
@role_required(['admin'])
@first_login_required
def reject_student(student_id):
    student = Student.query.get_or_404(student_id)
    student.status = 'rejected'
    
    db.session.commit()
    
    # Log activity
    log_activity(session['user_id'], 'Student Rejected', 
                f'Rejected student {student.full_name} ({student.roll_number})', 
                request.remote_addr)
    
    flash('Student rejected!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle-user/<int:user_id>')
@login_required
@role_required(['admin'])
@first_login_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('You cannot deactivate your own account!', 'error')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    log_activity(session['user_id'], f'User {status.title()}', 
                f'{status.title()} user {user.username}', 
                request.remote_addr)
    
    flash(f'User {status} successfully!', 'success')
    return redirect(url_for('manage_users'))


#TEACHER 
@app.route('/teacher/subjects')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_subjects():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    return render_template('teacher_subjects.html', subjects=subjects, teacher=teacher)

@app.route('/teacher/add-result', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def add_result():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        subject_id = request.form['subject_id']
        marks = float(request.form['marks'])
        comments = request.form.get('comments', '')
        
        # Validate marks
        if marks < 0 or marks > 100:
            flash('Marks must be between 0 and 100', 'error')
            return redirect(url_for('add_result'))
        
        # Check if result already exists
        existing_result = Result.query.filter_by(student_id=student_id, subject_id=subject_id).first()
        if existing_result:
            flash('Result already exists for this student and subject', 'error')
            return redirect(url_for('add_result'))
        
        # Calculate grade and GPA
        grade, gpa = calculate_grade_and_gpa(marks)
        
        # Create result
        result = Result(
            student_id=student_id,
            subject_id=subject_id,
            marks=marks,
            grade=grade,
            gpa=gpa,
            submitted_by=session['user_id'],
            comments=comments
        )
        
        db.session.add(result)
        db.session.commit()
        
        # Log activity
        student = Student.query.get(student_id)
        subject = Subject.query.get(subject_id)
        log_activity(session['user_id'], 'Result Added', 
                    f'Added result for {student.full_name} in {subject.subject_name} - Grade: {grade}', 
                    request.remote_addr)
        
        flash('Result added successfully! Waiting for academic approval.', 'success')
        return redirect(url_for('teacher_subjects'))
    
    # Get teacher's subjects and students
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    # Get students for the teacher's subjects
    students = db.session.query(Student).join(Result, Student.id == Result.student_id, isouter=True).join(
        Subject, Result.subject_id == Subject.id, isouter=True
    ).filter(
        Student.status == 'approved',
        Student.course.in_([s.course for s in subjects])
    ).distinct().all()
    
    return render_template('add_result.html', subjects=subjects, students=students, teacher=teacher)

@app.route('/teacher/my-results')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_results():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    # Get results submitted by this teacher
    results = db.session.query(Result, Student, Subject).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).filter(
        Result.submitted_by == session['user_id']
    ).order_by(Result.submitted_at.desc()).all()
    
    return render_template('teacher_results.html', results=results, teacher=teacher)

# ACADEMIC
@app.route('/academic/subjects')
@login_required
@role_required(['academic'])
@first_login_required
def academic_subjects():
    subjects = Subject.query.filter_by(is_active=True).all()
    teachers = Teacher.query.all()
    return render_template('academic_subjects.html', subjects=subjects, teachers=teachers)

@app.route('/academic/add-subject', methods=['GET', 'POST'])
@login_required
@role_required(['academic'])
@first_login_required
def add_subject():
    if request.method == 'POST':
        subject_code = request.form['subject_code'].strip().upper()
        subject_name = request.form['subject_name'].strip()
        semester = int(request.form['semester'])
        course = request.form['course']
        credits = int(request.form.get('credits', 3))
        teacher_id = request.form.get('teacher_id')
        
        # Check if subject code exists
        existing_subject = Subject.query.filter_by(subject_code=subject_code).first()
        if existing_subject:
            flash('Subject code already exists', 'error')
            return redirect(url_for('add_subject'))
        
        # Create subject
        subject = Subject(
            subject_code=subject_code,
            subject_name=subject_name,
            semester=semester,
            course=course,
            credits=credits,
            teacher_id=teacher_id if teacher_id else None,
            assigned_by=session['user_id']
        )
        
        db.session.add(subject)
        db.session.commit()
        
        # Log activity
        teacher_name = Teacher.query.get(teacher_id).full_name if teacher_id else 'Unassigned'
        log_activity(session['user_id'], 'Subject Added', 
                    f'Added subject {subject_name} ({subject_code}) - Teacher: {teacher_name}', 
                    request.remote_addr)
        
        flash('Subject added successfully!', 'success')
        return redirect(url_for('academic_subjects'))
    
    teachers = Teacher.query.all()
    return render_template('add_subject.html', courses=COURSES, teachers=teachers)

@app.route('/academic/assign-teacher/<int:subject_id>', methods=['POST'])
@login_required
@role_required(['academic'])
@first_login_required
def assign_teacher(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    teacher_id = request.form['teacher_id']
    
    if teacher_id:
        teacher = Teacher.query.get(teacher_id)
        subject.teacher_id = teacher_id
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Teacher Assigned', 
                    f'Assigned {teacher.full_name} to {subject.subject_name}', 
                    request.remote_addr)
        
        flash('Teacher assigned successfully!', 'success')
    else:
        subject.teacher_id = None
        db.session.commit()
        flash('Teacher unassigned from subject', 'info')
    
    return redirect(url_for('academic_subjects'))

@app.route('/academic/review-results')
@login_required
@role_required(['academic'])
@first_login_required
def review_results():
    # Get pending results
    pending_results = db.session.query(Result, Student, Subject, Teacher).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).join(
        Teacher, Subject.teacher_id == Teacher.id
    ).filter(
        Result.status == 'pending'
    ).order_by(Result.submitted_at.asc()).all()
    
    return render_template('review_results.html', pending_results=pending_results)

@app.route('/academic/approve-result/<int:result_id>')
@login_required
@role_required(['academic'])
@first_login_required
def approve_result(result_id):
    result = Result.query.get_or_404(result_id)
    
    # Check if result is already final
    if result.is_final:
        flash('This result is already final and cannot be modified', 'error')
        return redirect(url_for('review_results'))
    
    result.status = 'approved'
    result.approved_by = session['user_id']
    result.approved_at = datetime.utcnow()
    result.is_final = True  # Make it final once approved
    
    db.session.commit()
    
    # Log activity
    student = Student.query.get(result.student_id)
    subject = Subject.query.get(result.subject_id)
    log_activity(session['user_id'], 'Result Approved', 
                f'Approved result for {student.full_name} in {subject.subject_name} - Grade: {result.grade}', 
                request.remote_addr)
    
    flash('Result approved successfully!', 'success')
    return redirect(url_for('review_results'))


@app.route('/academic/reject-result/<int:result_id>', methods=['POST'])
@login_required
@role_required(['academic'])
@first_login_required
def reject_result(result_id):
    result = Result.query.get_or_404(result_id)
    comments = request.form.get('rejection_comments', '')
    
    # Check if result is already final
    if result.is_final:
        flash('This result is already final and cannot be modified', 'error')
        return redirect(url_for('review_results'))
    
    result.status = 'rejected'
    result.approved_by = session['user_id']
    result.approved_at = datetime.utcnow()
    result.comments = comments
    
    db.session.commit()
    
    # Log activity
    student = Student.query.get(result.student_id)
    subject = Subject.query.get(result.subject_id)
    log_activity(session['user_id'], 'Result Rejected', 
                f'Rejected result for {student.full_name} in {subject.subject_name} - Reason: {comments}', 
                request.remote_addr)
    
    flash('Result rejected!', 'info')
    return redirect(url_for('review_results'))

@app.route('/academic/all-results')
@login_required
@role_required(['academic'])
@first_login_required
def all_results():
    # Get all results with filters
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    status_filter = request.args.get('status', '')
    
    query = db.session.query(Result, Student, Subject, Teacher).join(
        Student, Result.student_id == Student.id
    ).join(
        Subject, Result.subject_id == Subject.id
    ).join(
        Teacher, Subject.teacher_id == Teacher.id, isouter=True
    )
    
    if course_filter:
        query = query.filter(Subject.course == course_filter)
    if semester_filter:
        query = query.filter(Subject.semester == int(semester_filter))
    if status_filter:
        query = query.filter(Result.status == status_filter)
    
    results = query.order_by(Result.submitted_at.desc()).all()
    
    return render_template('all_results.html', 
                         results=results, 
                         courses=COURSES, 
                         course_filter=course_filter, 
                         semester_filter=semester_filter, 
                         status_filter=status_filter)


@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        roll_number = request.form['roll_number'].strip().upper()
        full_name = request.form['full_name'].strip()
        course = request.form['course']
        semester = int(request.form['semester'])
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        # Check if username or roll number exists
        existing_user = User.query.filter_by(username=username).first()
        existing_student = Student.query.filter_by(roll_number=roll_number).first()
        
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        if existing_student:
            flash('Roll number already exists', 'error')
            return render_template('student_register.html', courses=COURSES)
        
        # Create user account
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role='student',
            first_login=False  #
        )
        db.session.add(new_user)
        db.session.flush()
        
        # Create student profile
        student = Student(
            user_id=new_user.id,
            roll_number=roll_number,
            full_name=full_name,
            course=course,
            semester=semester
        )
        db.session.add(student)
        db.session.commit()
        
        # Log activity
        log_activity(new_user.id, 'Student Registration', 
                    f'Student {full_name} ({roll_number}) registered for {course}', 
                    request.remote_addr)
        
        flash('Registration successful! Please wait for admin approval before logging in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('student_register.html', courses=COURSES)


@app.route('/student/transcript')
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def student_transcript():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    # Get all approved results
    results = db.session.query(Result, Subject).join(Subject).filter(
        Result.student_id == student.id,
        Result.status == 'approved'
    ).order_by(Subject.semester, Subject.subject_name).all()

    transcript_data = {}
    overall_gpa = 0
    overall_credits = 0
    passed_subjects = 0
    total_subjects = 0
    
    # Track best and worst subjects
    best_subject = None
    worst_subject = None
    
    for result, subject in results:
        semester = subject.semester
        if semester not in transcript_data:
            transcript_data[semester] = {
                'subjects': [],
                'semester_gpa': 0,
                'semester_credits': 0,
                'semester_points': 0
            }
        
        # Add subject to semester
        subject_entry = {
            'subject_code': subject.subject_code,
            'subject_name': subject.subject_name,
            'credits': subject.credits,
            'grade': result.grade,
            'gpa': result.gpa,
            'marks': result.marks
        }
        transcript_data[semester]['subjects'].append(subject_entry)
        
        # Update semester totals
        transcript_data[semester]['semester_points'] += result.gpa * subject.credits
        transcript_data[semester]['semester_credits'] += subject.credits
        
        # Update overall totals
        overall_gpa += result.gpa * subject.credits
        overall_credits += subject.credits
        total_subjects += 1
        
        # Track passed subjects
        if result.gpa >= 1.0:  # Minimum passing GPA
            passed_subjects += 1
        
        # Track best and worst subjects
        if not best_subject or result.gpa > best_subject['gpa']:
            best_subject = {
                'subject': subject.subject_name,
                'grade': result.grade,
                'gpa': result.gpa,
                'marks': result.marks
            }
            
        if not worst_subject or result.gpa < worst_subject['gpa']:
            worst_subject = {
                'subject': subject.subject_name,
                'grade': result.grade,
                'gpa': result.gpa,
                'marks': result.marks
            }
    
    # semester GPAs
    for semester in transcript_data:
        if transcript_data[semester]['semester_credits'] > 0:
            transcript_data[semester]['semester_gpa'] = transcript_data[semester]['semester_points'] / transcript_data[semester]['semester_credits']
    
    # GPA
    overall_gpa = overall_gpa / overall_credits if overall_credits > 0 else 0
    
    # pass rate
    pass_rate = round((passed_subjects / total_subjects) * 100, 1) if total_subjects > 0 else 0
  
    sorted_semesters = sorted(transcript_data.keys())
    
    return render_template('student_transcript.html',
                         student=student,
                         transcript_data=transcript_data,
                         sorted_semesters=sorted_semesters,
                         overall_gpa=round(overall_gpa, 2),
                         overall_credits=overall_credits,
                         passed_subjects=passed_subjects,
                         total_subjects=total_subjects,
                         pass_rate=pass_rate,
                         best_subject=best_subject,
                         worst_subject=worst_subject,
                         now=datetime.now().strftime("%B %d, %Y"))


@app.route('/student/results')
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def student_results():
  
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if not student:
        flash('Student profile not found', 'error')
        return redirect(url_for('logout'))
    
    # Get the associated user object for profile picture
    user = User.query.get(session['user_id'])
    
    # Get approved results
    results = db.session.query(Result, Subject).join(Subject).filter(
        Result.student_id == student.id,
        Result.status == 'approved'
    ).order_by(Subject.semester, Subject.subject_name).all()
    
    # Group results by semester
    results_by_semester = {}
    total_gpa = 0
    total_credits = 0
    passed_subjects = 0
    total_subjects = 0
    best_grade = 'F'
    
    for result, subject in results:
        semester = subject.semester
        if semester not in results_by_semester:
            results_by_semester[semester] = {
                'results': [],
                'semester_gpa': 0,
                'semester_credits': 0
            }
        
        results_by_semester[semester]['results'].append({
            'subject': subject,
            'result': result
        })
        
        # Calculate GPA
        results_by_semester[semester]['semester_gpa'] += result.gpa * subject.credits
        results_by_semester[semester]['semester_credits'] += subject.credits
        total_gpa += result.gpa * subject.credits
        total_credits += subject.credits
        
        total_subjects += 1
        if result.gpa > 0:  # Passed if GPA > 0
            passed_subjects += 1
            
        if grade_to_value(result.grade) > grade_to_value(best_grade):
            best_grade = result.grade
    
    for semester in results_by_semester:
        if results_by_semester[semester]['semester_credits'] > 0:
            results_by_semester[semester]['semester_gpa'] /= results_by_semester[semester]['semester_credits']
        overall_gpa = total_gpa / total_credits if total_credits > 0 else 0
    
    pass_rate = round((passed_subjects / total_subjects) * 100, 2) if total_subjects > 0 else 0
    
    return render_template('student_results.html',
                         student=student,
                         user=user,  # Pass user object for profile picture
                         results_by_semester=results_by_semester,
                         overall_gpa=round(overall_gpa, 2),
                         total_credits=total_credits,
                         passed_subjects=passed_subjects,
                         total_subjects=total_subjects,
                         best_subject_grade=best_grade,
                         pass_rate=pass_rate)

# Helper function to convert grade to numerical value
def grade_to_value(grade):
    grade_values = {
        'A+': 12, 'A': 11, 'A-': 10,
        'B+': 9, 'B': 8, 'B-': 7,
        'C+': 6, 'C': 5, 'C-': 4,
        'D+': 3, 'D': 2, 'F': 0
    }
    return grade_values.get(grade, 0)


# API ROUTES 
@app.route('/api/students-by-course/<course>')
@login_required
@role_required(['teacher', 'academic'])
def api_students_by_course(course):
    students = Student.query.filter_by(course=course, status='approved').all()
    return jsonify([{
        'id': s.id,
        'roll_number': s.roll_number,
        'full_name': s.full_name,
        'semester': s.semester
    } for s in students])

@app.route('/api/subjects-by-course-semester')
@login_required
@role_required(['teacher', 'academic'])
def api_subjects_by_course_semester():
    course = request.args.get('course')
    semester = request.args.get('semester')
    
    query = Subject.query.filter_by(is_active=True)
    if course:
        query = query.filter_by(course=course)
    if semester:
        query = query.filter_by(semester=int(semester))
    
    subjects = query.all()
    return jsonify([{
        'id': s.id,
        'subject_code': s.subject_code,
        'subject_name': s.subject_name,
        'credits': s.credits
    } for s in subjects])

#  REPORTS ROUTES


@app.route('/reports')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def reports():
    return render_template(
        'reports.html',
        now=datetime.now(),
        total_courses=len(COURSES),  
        # ... other variables
    )

@app.route('/reports/course-performance')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def course_performance_report():
    course_stats = {}
    
    for course in COURSES:
        results = db.session.query(Result, Subject, Student).join(
            Subject, Result.subject_id == Subject.id
        ).join(
            Student, Result.student_id == Student.id
        ).filter(
            Subject.course == course,
            Result.status == 'approved'
        ).all()
        
        if results:
            total_students = len(set([r[2].id for r in results]))
            total_marks = sum([r[0].marks for r in results])
            average_marks = total_marks / len(results)
            
            # Grade distribution
            grades = {}
            for result, _, _ in results:
                grade = result.grade
                grades[grade] = grades.get(grade, 0) + 1
            
            course_stats[course] = {
    
                'total_students': total_students,
                'total_results': len(results),
                'average_marks': round(average_marks, 2),
                'grade_distribution': grades
            }
    
    return render_template('course_performance_report.html', course_stats=course_stats)

@app.route('/reports/teacher-performance')
@login_required
@role_required(['admin', 'academic'])
@first_login_required
def teacher_performance_report():
    # Get performance statistics by teacher
    teachers = Teacher.query.all()
    teacher_stats = {}
    
    for teacher in teachers:
        # Get results submitted by this teacher
        results = db.session.query(Result, Subject).join(
            Subject, Result.subject_id == Subject.id
        ).filter(
            Subject.teacher_id == teacher.id,
            Result.status == 'approved'
        ).all()
        
        if results:
            total_results = len(results)
            total_marks = sum([r[0].marks for r in results])
            average_marks = total_marks / total_results
            
            # Get subjects taught
            subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).count()
            
            teacher_stats[teacher.id] = {
                'teacher': teacher,
                'subjects_taught': subjects,
                'total_results': total_results,
                'average_marks': round(average_marks, 2)
            }
    
    return render_template('teacher_performance_report.html', teacher_stats=teacher_stats)




# Add these constants after your existing constants
EVENT_TYPES = {
    'lecture': {'name': 'Lecture', 'color': '#007bff'},
    'exam': {'name': 'Exam', 'color': '#dc3545'},
    'holiday': {'name': 'Holiday', 'color': '#28a745'},
    'practical': {'name': 'Practical Session', 'color': '#ffc107'},
    'assessment': {'name': 'Internal Assessment', 'color': '#6f42c1'}
}

PRIORITY_LEVELS = {
    'low': {'name': 'Low', 'color': '#6c757d'},
    'normal': {'name': 'Normal', 'color': '#007bff'},
    'high': {'name': 'High', 'color': '#fd7e14'},
    'urgent': {'name': 'Urgent', 'color': '#dc3545'}
}

# Add these utility functions
def create_notification(user_id, title, message, notification_type, reference_id=None):
    """Create a new notification"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=notification_type,
        reference_id=reference_id
    )
    db.session.add(notification)
    db.session.commit()

def get_user_targets(user):
    """Get user's target criteria for filtering events/announcements"""
    targets = []
    
    if user.role == 'student':
        student = Student.query.filter_by(user_id=user.id).first()
        if student:
            targets.extend([
                ('course', student.course),
                ('semester', str(student.semester))
            ])
    elif user.role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=user.id).first()
        if teacher:
            targets.append(('department', teacher.department))
    elif user.role == 'academic':
        academic = Academic.query.filter_by(user_id=user.id).first()
        if academic:
            targets.append(('department', academic.department))
    
    return targets

def allowed_file_announcement(filename):
    """Check if uploaded file is allowed for announcements"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'pdf', 'docx', 'doc', 'txt'}

# Add this to your app configuration

@app.route('/notifications/delete/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    """Delete a single notification"""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(notification)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(user_id=session['user_id'], is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/notifications/delete-all', methods=['DELETE'])
@login_required
def delete_all_notifications():
    """Delete all notifications for the user"""
    Notification.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/calendar')
@login_required
@first_login_required
@student_approved_required
def calendar():
    """Main calendar view"""
    user = User.query.get(session['user_id'])
    targets = get_user_targets(user)
    
    # Get events based on user's targets
    events_query = CalendarEvent.query.filter_by(is_active=True)
    
    # Add target filtering
    filters = [CalendarEvent.target_type == 'all']
    for target_type, target_value in targets:
        filters.append(db.and_(
            CalendarEvent.target_type == target_type,
            CalendarEvent.target_value == target_value
        ))
    
    events = events_query.filter(db.or_(*filters)).order_by(CalendarEvent.start_date).all()
    
    return render_template('calendar.html', 
                         events=events, 
                         event_types=EVENT_TYPES,
                         user=user)

@app.route('/api/calendar-events')
@login_required
def api_calendar_events():
    """API endpoint for calendar events (for FullCalendar.js)"""
    user = User.query.get(session['user_id'])
    targets = get_user_targets(user)
    
    # Get events based on user's targets
    events_query = CalendarEvent.query.filter_by(is_active=True)
    
    # Add target filtering
    filters = [CalendarEvent.target_type == 'all']
    for target_type, target_value in targets:
        filters.append(db.and_(
            CalendarEvent.target_type == target_type,
            CalendarEvent.target_value == target_value
        ))
    
    events = events_query.filter(db.or_(*filters)).all()
    
    # Format for FullCalendar
    calendar_events = []
    for event in events:
        calendar_events.append({
            'id': event.id,
            'title': event.title,
            'start': event.start_date.isoformat(),
            'end': event.end_date.isoformat(),
            'color': event.color,
            'extendedProps': {
                'description': event.description,
                'type': event.event_type,
                'target': f"{event.target_type}: {event.target_value}" if event.target_value else "All"
            }
        })
    
    return jsonify(calendar_events)

@app.route('/calendar/add-event', methods=['GET', 'POST'])
@login_required
@role_required(['academic', 'teacher'])
@first_login_required
def add_calendar_event():
    """Add new calendar event"""
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form.get('description', '').strip()
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%dT%H:%M')
        event_type = request.form['event_type']
        target_type = request.form['target_type']
        target_value = request.form.get('target_value', '')
        reminder_time = int(request.form.get('reminder_time', 30))
        
        # Validate dates
        if start_date >= end_date:
            flash('End date must be after start date', 'error')
            return redirect(url_for('add_calendar_event'))
        
        # Create event
        event = CalendarEvent(
            title=title,
            description=description,
            start_date=start_date,
            end_date=end_date,
            event_type=event_type,
            color=EVENT_TYPES[event_type]['color'],
            target_type=target_type,
            target_value=target_value if target_type != 'all' else None,
            created_by=session['user_id'],
            reminder_time=reminder_time
        )
        
        db.session.add(event)
        db.session.commit()
        
        # Create notifications for affected users
        create_event_notifications(event)
        
        # Log activity
        log_activity(session['user_id'], 'Calendar Event Created', 
                    f'Created event: {title} for {target_type}', 
                    request.remote_addr)
        
        flash('Calendar event created successfully!', 'success')
        return redirect(url_for('calendar'))
    
    return render_template('add_calendar_event.html', 
                         event_types=EVENT_TYPES,
                         courses=COURSES,
                         departments=DEPARTMENTS)

@app.route('/calendar/import-events', methods=['GET', 'POST'])
@login_required
@role_required(['academic', 'teacher'])
@first_login_required
def import_calendar_events():
    """Import calendar events from CSV/Excel file"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('import_calendar_events'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('import_calendar_events'))
        
        if file and allowed_file_announcement(file.filename):
            filename = secure_filename(f"calendar_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['ANNOUNCEMENT_UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Process CSV file
                if filename.endswith('.csv'):
                    import csv
                    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                        reader = csv.DictReader(csvfile)
                        events_created = 0
                        
                        for row in reader:
                            try:
                                event = CalendarEvent(
                                    title=row['title'],
                                    description=row.get('description', ''),
                                    start_date=datetime.strptime(row['start_date'], '%Y-%m-%d %H:%M'),
                                    end_date=datetime.strptime(row['end_date'], '%Y-%m-%d %H:%M'),
                                    event_type=row.get('event_type', 'lecture'),
                                    color=EVENT_TYPES.get(row.get('event_type', 'lecture'), EVENT_TYPES['lecture'])['color'],
                                    target_type=row.get('target_type', 'all'),
                                    target_value=row.get('target_value', ''),
                                    created_by=session['user_id']
                                )
                                db.session.add(event)
                                events_created += 1
                            except Exception as e:
                                continue
                        
                        db.session.commit()
                        flash(f'Successfully imported {events_created} events!', 'success')
                
                # Clean up file
                os.remove(file_path)
                
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            flash('Invalid file type. Please upload CSV files only.', 'error')
        
        return redirect(url_for('calendar'))
    
    return render_template('import_calendar_events.html')

# ===== ANNOUNCEMENT ROUTES =====


# Add this function in your app.py (before routes)
@app.template_filter('format_datetime')
def format_datetime_filter(value, format="%B %d, %Y at %I:%M %p"):
    """Format a datetime object to a readable string."""
    if value is None:
        return ""
    try:
        # If it's already a datetime object
        if isinstance(value, datetime):
            return value.strftime(format)
        # If it's a string representation, convert to datetime first
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime(format)
    except (TypeError, ValueError):
        return str(value)  # Fallback to string representation




@app.route('/announcements')
@login_required
@first_login_required
@student_approved_required
def announcements():
    user = User.query.get(session['user_id'])
    targets = get_user_targets(user)
    
    # Create base query - FIXED: Use 'creator' instead of 'author'
    query = Announcement.query.filter_by(is_active=True).options(db.joinedload(Announcement.creator))
    
    # Build target filters
    filters = [Announcement.target_type == 'all']
    announcements = query.filter(db.or_(*filters))\
    .order_by(Announcement.created_at.desc())\
    .all()
    
    if targets:
        for target_type, target_value in targets:
            filters.append(
                db.and_(
                    Announcement.target_type == target_type,
                    Announcement.target_value == str(target_value)
                )
            )
    
    # Apply filters and ordering
    announcements = query.filter(db.or_(*filters)).order_by(Announcement.created_at.desc()).all()
    
    # Calculate unread count
    unread_count = Notification.query.filter_by(
        user_id=user.id,
        is_read=False
    ).count()
    
    # Calculate priority counts
    priority_counts = {
        'high': 0,
        'medium': 0,
        'low': 0,
    }
    
    for a in announcements:
        if a.priority == 'high':
            priority_counts['high'] += 1
        elif a.priority == 'medium':
            priority_counts['medium'] += 1
        elif a.priority == 'low':
            priority_counts['low'] += 1
    
    # Calculate percentages
    total = len(announcements)
    if total > 0:
        priority_counts['high_perc'] = round((priority_counts['high'] / total) * 100)
        priority_counts['medium_perc'] = round((priority_counts['medium'] / total) * 100)
        priority_counts['low_perc'] = round((priority_counts['low'] / total) * 100)
    else:
        priority_counts['high_perc'] = priority_counts['medium_perc'] = priority_counts['low_perc'] = 0
    
    # Mark announcements as read
    for announcement in announcements:
        existing_read = AnnouncementRead.query.filter_by(
            announcement_id=announcement.id,
            user_id=user.id
        ).first()
        
        if not existing_read:
            read_record = AnnouncementRead(
                announcement_id=announcement.id,
                user_id=user.id
            )
            db.session.add(read_record)
    
    db.session.commit()
    
    return render_template('announcements.html', 
                         announcements=announcements,
                         priority_levels=PRIORITY_LEVELS,
                         user=user,
                         unread_count=unread_count,
                         priority_counts=priority_counts)

@app.route('/announcements/add', methods=['GET', 'POST'])
@login_required
@role_required(['academic', 'teacher'])
@first_login_required
def add_announcement():
    """Add new announcement"""
    # Get user object - THIS WAS MISSING
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        priority = request.form['priority']
        target_type = request.form['target_type']
        target_value = request.form.get('target_value', '')
        expires_at = request.form.get('expires_at')
        
        # Handle file upload
        attachment_path = None
        attachment_name = None
        attachment_type = None
        
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file.filename and allowed_file_announcement(file.filename):
                filename = secure_filename(f"announcement_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                attachment_path = os.path.join(app.config['ANNOUNCEMENT_UPLOAD_FOLDER'], filename)
                file.save(attachment_path)
                attachment_name = file.filename
                attachment_type = file.filename.rsplit('.', 1)[1].lower()
        
        # Create announcement
        announcement = Announcement(
            title=title,
            content=content,
            priority=priority,
            target_type=target_type,
            target_value=target_value if target_type != 'all' else None,
            expires_at=datetime.strptime(expires_at, '%Y-%m-%d') if expires_at else None,
            created_by=session['user_id'],
            attachment_path=attachment_path,
            attachment_name=attachment_name,
            attachment_type=attachment_type
        )
        
        db.session.add(announcement)
        db.session.commit()
        
        # Create notifications for affected users
        create_announcement_notifications(announcement)
        
        # Log activity
        log_activity(session['user_id'], 'Announcement Created', 
                    f'Created announcement: {title} for {target_type}', 
                    request.remote_addr)
        
        flash('Announcement created successfully!', 'success')
        return redirect(url_for('announcements'))
    
    # Pass user object to template - THIS WAS MISSING
    return render_template('add_announcement.html', 
                         priority_levels=PRIORITY_LEVELS,
                         courses=COURSES,
                         departments=DEPARTMENTS,
                         user=user)  # <- Added user parameter

@app.route('/announcements/download/<int:announcement_id>')
@login_required
@first_login_required
def download_announcement_attachment(announcement_id):
    """Download announcement attachment"""
    announcement = Announcement.query.get_or_404(announcement_id)
    
    # Check if user has access to this announcement
    user = User.query.get(session['user_id'])
    targets = get_user_targets(user)
    
    has_access = (announcement.target_type == 'all' or 
                  any(announcement.target_type == target_type and 
                      announcement.target_value == target_value 
                      for target_type, target_value in targets))
    
    if not has_access:
        flash('Access denied', 'error')
        return redirect(url_for('announcements'))
    
    if announcement.attachment_path and os.path.exists(announcement.attachment_path):
        return send_file(announcement.attachment_path, 
                        as_attachment=True, 
                        download_name=announcement.attachment_name)
    else:
        flash('File not found', 'error')
        return redirect(url_for('announcements'))




@app.route('/notifications')
@login_required
@first_login_required
def notifications():
    """View notifications"""
    try:
        # Get user ID safely
        user_id = current_user.id if current_user and current_user.is_authenticated else session.get('user_id')
        
        if not user_id:
            return redirect(url_for('login'))
        
        # Get notifications with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        user_notifications = Notification.query.filter_by(
            user_id=user_id
        ).order_by(Notification.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get unread count before marking as read
        unread_count = Notification.query.filter_by(
            user_id=user_id,
            is_read=False
        ).count()
        
        Notification.query.filter_by(
            user_id=user_id,
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        return render_template('notifications.html', 
                             notifications=user_notifications,
                             unread_count=unread_count)
    
    except Exception as e:
        app.logger.error(f"Error loading notifications: {str(e)}")
        if 'db' in globals():
            db.session.rollback()
        return render_template('error.html', error="Unable to load notifications"), 500

@app.route('/api/notifications/count')
@login_required
def api_notifications_count():
    """Get unread notifications count"""
    try:
        user_id = current_user.id if current_user and current_user.is_authenticated else session.get('user_id')
        
        if not user_id:
            return jsonify({'count': 0, 'error': 'User not authenticated'}), 401
        
        count = Notification.query.filter_by(
            user_id=user_id,
            is_read=False
        ).count()
        
        return jsonify({'count': count, 'status': 'success'})
        
    except Exception as e:
        app.logger.error(f"Error getting notification count: {str(e)}")
        return jsonify({'count': 0, 'error': 'Server error'}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    try:
        user_id = current_user.id if current_user and current_user.is_authenticated else session.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=user_id
        ).first()
        
        if not notification:
            return jsonify({'error': 'Notification not found'}), 404
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Notification marked as read'})
        
    except Exception as e:
        app.logger.error(f"Error marking notification as read: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_readed():
    """Mark all notifications as read"""
    try:
        user_id = current_user.id if current_user and current_user.is_authenticated else session.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        Notification.query.filter_by(
            user_id=user_id,
            is_read=False
        ).update({'is_read': True})
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'All notifications   as read'})
        
    except Exception as e:
        app.logger.error(f"Error all notifications as read: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500

# ===== NOTIFICATION HELPER FUNCTIONS =====
def create_event_notifications(event):
    """Create notifications for calendar event"""
    try:
        # Get affected users
        affected_users = get_affected_users(event.target_type, event.target_value)
        
        for user in affected_users:
            create_notification(
                user_id=user.id,
                title=f"New Calendar Event: {event.title}",
                message=f"A new {EVENT_TYPES.get(event.event_type, {}).get('name', 'event')} has been scheduled for {event.start_date.strftime('%B %d, %Y at %I:%M %p')}",
                notification_type='calendar',
                reference_id=event.id
            )
    except Exception as e:
        app.logger.error(f"Error creating event notifications: {str(e)}")

def create_announcement_notifications(announcement):
    """Create notifications for announcement"""
    try:
        # Get affected users
        affected_users = get_affected_users(announcement.target_type, announcement.target_value)
        
        for user in affected_users:
            create_notification(
                user_id=user.id,
                title=f"New Announcement: {announcement.title}",
                message=f"A new {announcement.priority} priority announcement has been posted",
                notification_type='announcement',
                reference_id=announcement.id
            )
    except Exception as e:
        app.logger.error(f"Error creating announcement notifications: {str(e)}")

def create_notification(user_id, title, message, notification_type='general', reference_id=None):
    """Create a new notification"""
    try:
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            reference_id=reference_id,
            is_read=False,
            created_at=datetime.utcnow()
        )
        
        db.session.add(notification)
        db.session.commit()
        
        return notification
        
    except Exception as e:
        app.logger.error(f"Error creating notification: {str(e)}")
        db.session.rollback()
        return None

def get_affected_users(target_type, target_value):
    """Get users affected by notifications based on target type and value"""
    try:
        if target_type == 'all':
            return User.query.filter_by(is_active=True).all()
        elif target_type == 'role':
            return User.query.filter_by(role=target_value, is_active=True).all()
        elif target_type == 'department':
            return User.query.filter_by(department=target_value, is_active=True).all()
        elif target_type == 'user':
            user = User.query.filter_by(id=target_value, is_active=True).first()
            return [user] if user else []
        else:
            return []
    except Exception as e:
        app.logger.error(f"Error getting affected users: {str(e)}")
        return []


def generate_qr_secret():
    """Generate a secure random secret for QR code"""
    return secrets.token_urlsafe(32)

def generate_backup_pin():
    """Generate a 6-digit backup PIN"""
    return f"{secrets.randbelow(900000) + 100000:06d}"

def create_qr_payload(lesson_id, secret, expiry):
    """Create QR code payload with HMAC signature"""
    payload = {
        'lesson_id': lesson_id,
        'secret': secret,
        'expiry': expiry.isoformat()
    }
    
    # Create HMAC signature
    message = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        app.config['SECRET_KEY'],
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    payload['signature'] = signature
    return base64.b64encode(json.dumps(payload).encode()).decode()

def verify_qr_payload(qr_data):
    """Verify QR code payload and signature"""
    try:
        payload = json.loads(base64.b64decode(qr_data).decode())
        
        # Extract signature
        signature = payload.pop('signature')
        
        # Verify signature
        message = json.dumps(payload, sort_keys=True)
        expected_signature = hmac.new(
            app.config['SECRET_KEY'].encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return None, "Invalid signature"
        
        # Check expiry
        expiry = datetime.fromisoformat(payload['expiry'])
        if datetime.utcnow() > expiry:
            return None, "QR code expired"
        
        return payload, None
        
    except Exception as e:
        return None, f"Invalid QR data: {str(e)}"

def generate_qr_image(qr_data):
    """Generate QR code image"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="navy", back_color="lavender") 
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return base64.b64encode(img_io.getvalue()).decode()

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two points in meters"""
    from math import radians, cos, sin, asin, sqrt
    
    # Convert to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    
    r = 6371000
    return c * r

# ===== TEACHER ATTENDANCE ROUTES =====
@app.route('/teacher/lessons')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_lessons():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    # Get lessons for this teacher
    lessons = Lesson.query.filter_by(teacher_id=teacher.id)\
                         .order_by(Lesson.date_time.desc())\
                         .all()
    
    return render_template('teacher_lessons.html', lessons=lessons, teacher=teacher)

@app.route('/teacher/create-lesson', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def create_lesson():
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form.get('description', '').strip()
        subject_id = request.form['subject_id']
        date_time = datetime.strptime(request.form['date_time'], '%Y-%m-%dT%H:%M')
        duration = int(request.form.get('duration', 120))
        location = request.form.get('location', '').strip()
        max_scans = request.form.get('max_scans')
        
        # Geo-fencing (optional)
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        geo_radius = float(request.form.get('geo_radius', 100))
        
        # Validate subject belongs to teacher
        subject = Subject.query.filter_by(id=subject_id, teacher_id=teacher.id).first()
        if not subject:
            flash('Invalid subject selected', 'error')
            return redirect(url_for('create_lesson'))
        
        # Generate QR secret and PIN
        qr_secret = generate_qr_secret()
        backup_pin = generate_backup_pin()
        qr_expiry = date_time + timedelta(minutes=duration + 15)  # 15 min grace period
        
        # Create lesson - FIXED: Added subject_id assignment
        lesson = Lesson(
            title=title,
            description=description,
            subject_id=subject_id,  # This was previously commented out
            teacher_id=teacher.id,
            date_time=date_time,
            duration=duration,
            location=location,
            max_scans=int(max_scans) if max_scans else None,
            qr_secret=qr_secret,
            backup_pin=backup_pin,
            qr_expiry=qr_expiry,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            geo_radius=geo_radius
        )
        
        db.session.add(lesson)
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Lesson Created', 
                    f'Created lesson: {title} for {subject.subject_name}', 
                    request.remote_addr)
        
        flash('Lesson created successfully!', 'success')
        return redirect(url_for('lesson_details', lesson_id=lesson.id))
    
    # Get teacher's subjects
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    return render_template('create_lesson.html', subjects=subjects, teacher=teacher)

@app.route('/teacher/lesson/<int:lesson_id>')
@login_required
@role_required(['teacher'])
@first_login_required
def lesson_details(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    # Verify lesson belongs to this teacher
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    # Get attendance records
    attendance_records = db.session.query(Attendance, Student, User)\
        .join(Student, Attendance.student_id == Student.id)\
        .join(User, Student.user_id == User.id)\
        .filter(Attendance.lesson_id == lesson_id)\
        .order_by(Attendance.scan_time.asc())\
        .all()
    
    # Get expected students (enrolled in the course)
    expected_students = Student.query.filter_by(
        course=lesson.subject.course,
        semester=lesson.subject.semester,
        status='approved'
    ).all()
    
    # Generate QR code if lesson is active
    qr_image = None
    if lesson.status == 'active' and lesson.qr_expiry > datetime.utcnow():
        qr_data = create_qr_payload(lesson.id, lesson.qr_secret, lesson.qr_expiry)
        qr_image = generate_qr_image(qr_data)
    
    # Calculate statistics
    total_expected = len(expected_students)
    total_present = len(attendance_records)
    attendance_rate = (total_present / total_expected * 100) if total_expected > 0 else 0
    
    return render_template('lesson_details.html', 
                         lesson=lesson, 
                         attendance_records=attendance_records,
                         expected_students=expected_students,
                         qr_image=qr_image,
                         total_expected=total_expected,
                         total_present=total_present,
                         attendance_rate=attendance_rate)

@app.route('/teacher/lesson/<int:lesson_id>/activate', methods=['POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def activate_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    lesson.status = 'active'
    db.session.commit()
    
    log_activity(session['user_id'], 'Lesson Activated', 
                f'Activated lesson: {lesson.title}', 
                request.remote_addr)
    
    flash('Lesson activated! Students can now scan QR code.', 'success')
    return redirect(url_for('lesson_details', lesson_id=lesson_id))

@app.route('/teacher/lesson/<int:lesson_id>/pause', methods=['POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def pause_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    lesson.status = 'paused'
    db.session.commit()
    
    flash('Lesson paused. QR scanning is temporarily disabled.', 'info')
    return redirect(url_for('lesson_details', lesson_id=lesson_id))

@app.route('/teacher/lesson/<int:lesson_id>/extend', methods=['POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def extend_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    # Extend by 15 minutes
    lesson.qr_expiry = lesson.qr_expiry + timedelta(minutes=15)
    lesson.duration += 15
    db.session.commit()
    
    flash('Lesson extended by 15 minutes.', 'success')
    return redirect(url_for('lesson_details', lesson_id=lesson_id))

@app.route('/teacher/lesson/<int:lesson_id>/manual-attendance', methods=['POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def manual_attendance(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    student_id = request.form['student_id']
    status = request.form['status']
    notes = request.form.get('notes', '')
    
    # Check if attendance already exists
    existing_attendance = Attendance.query.filter_by(
        lesson_id=lesson_id,
        student_id=student_id
    ).first()
    
    if existing_attendance:
        # Update existing record
        existing_attendance.status = status
        existing_attendance.scan_method = 'manual'
        existing_attendance.validation_notes = notes
        existing_attendance.verified_by = session['user_id']
        existing_attendance.updated_at = datetime.utcnow()
    else:
        # Create new record
        attendance = Attendance(
            lesson_id=lesson_id,
            student_id=student_id,
            status=status,
            scan_method='manual',
            validation_notes=notes,
            verified_by=session['user_id'],
            ip_address=request.remote_addr
        )
        db.session.add(attendance)
    
    db.session.commit()
    
    student = Student.query.get(student_id)
    log_activity(session['user_id'], 'Manual Attendance', 
                f'Manually marked {student.full_name} as {status} for {lesson.title}', 
                request.remote_addr)
    
    flash('Attendance updated successfully!', 'success')
    return redirect(url_for('lesson_details', lesson_id=lesson_id))

@app.route('/teacher/lesson/<int:lesson_id>/export/<format>')
@login_required
@role_required(['teacher'])
@first_login_required
def export_attendance(lesson_id, format):
    lesson = Lesson.query.get_or_404(lesson_id)
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    if lesson.teacher_id != teacher.id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_lessons'))
    
    # Get attendance data
    attendance_data = db.session.query(Attendance, Student, User)\
        .join(Student, Attendance.student_id == Student.id)\
        .join(User, Student.user_id == User.id)\
        .filter(Attendance.lesson_id == lesson_id)\
        .order_by(Student.roll_number.asc())\
        .all()
    
    if format == 'csv':
        return export_attendance_csv(lesson, attendance_data)
    elif format == 'excel':
        # Excel export not implemented, fallback to CSV
        flash('Excel export is not implemented. Downloading CSV instead.', 'warning')
        return export_attendance_csv(lesson, attendance_data)
    elif format == 'pdf':
        flash('PDF export is not implemented. Downloading CSV instead.', 'warning')
        return export_attendance_csv(lesson, attendance_data)
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('lesson_details', lesson_id=lesson_id))

def export_attendance_csv(lesson, attendance_data):
    """Export attendance as CSV"""
   
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Roll Number', 'Student Name', 'Status', 'Scan Time', 
        'Scan Method', 'Validation Notes'
    ])
    
    # Write data
    for attendance, student, user in attendance_data:
        writer.writerow([
            student.roll_number,
            student.full_name,
            attendance.status,
            attendance.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            attendance.scan_method,
            attendance.validation_notes or ''
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=attendance_{lesson.id}_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    )


@app.route('/teacher/send-attendance-report/<int:lesson_id>', methods=['POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def send_attendance_report(lesson_id):
    try:
        lesson = Lesson.query.get_or_404(lesson_id)
        teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
        
        if lesson.teacher_id != teacher.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_lessons'))
        
        recipients = request.form.getlist('recipients')
        message = request.form.get('message', '')
        
        # Get attendance data with student details
        attendance_data = db.session.query(Attendance, Student, User)\
            .join(Student, Attendance.student_id == Student.id)\
            .join(User, Student.user_id == User.id)\
            .filter(Attendance.lesson_id == lesson_id)\
            .order_by(Student.roll_number)\
            .all()
        
        # Process recipients
        if 'academic' in recipients:
            send_to_academic_staff(lesson, attendance_data, message)
        
        if 'students' in recipients:
            send_to_students(lesson, attendance_data, message)
        
        flash('Attendance report sent successfully!', 'success')
        return redirect(url_for('lesson_details', lesson_id=lesson_id))
        
    except Exception as e:
        app.logger.error(f"Error sending attendance report: {str(e)}")
        flash('Failed to send attendance report', 'error')
        return redirect(url_for('lesson_details', lesson_id=lesson_id))

def send_to_academic_staff(lesson, attendance_data, message):
    """Send attendance report to academic staff"""
    academic_users = User.query.filter_by(role='academic', is_active=True).all()
    
    for user in academic_users:
        try:
            # Create email message
            msg = Message(
                subject=f"Attendance Report for {lesson.title}",
                recipients=[user.email],
                sender=app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            # Render HTML and plain text versions
            msg.html = render_template(
                'email/academic_report.html',
                lesson=lesson,
                data=attendance_data,
                message=message,
                teacher=lesson.teacher
            )
            msg.body = render_template(
                'email/academic_report.txt',
                lesson=lesson,
                data=attendance_data,
                message=message,
                teacher=lesson.teacher
            )
            
            mail.send(msg)
            
            # Create notification
            create_notification(
                user_id=user.id,
                title=f"Attendance Report: {lesson.title}",
                message=f"Attendance report for {lesson.title} has been sent to you",
                notification_type='attendance'
            )
            
            # Log activity
            log_activity(
                session['user_id'],
                'Report Sent to Academic',
                f'Sent attendance report for {lesson.title} to {user.username}',
                request.remote_addr
            )
            
        except Exception as e:
            app.logger.error(f"Failed to send to academic staff {user.email}: {str(e)}")

def send_to_students(lesson, attendance_data, message):
    """Send individual attendance status to students"""
    for attendance, student, user in attendance_data:
        try:
            # Only send to students who have email
            if not user.email:
                continue
                
            # Create email message
            msg = Message(
                subject=f"Your Attendance for {lesson.title}",
                recipients=[user.email],
                sender=app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            # Render HTML and plain text versions
            msg.html = render_template(
                'email/student_report.html',
                lesson=lesson,
                attendance=attendance,
                student=student,
                message=message
            )
            msg.body = render_template(
                'email/student_report.txt',
                lesson=lesson,
                attendance=attendance,
                student=student,
                message=message
            )
            
            # Send email
            mail.send(msg)
            
            # Create notification
            create_notification(
                user_id=user.id,
                title=f"Attendance Update: {lesson.title}",
                message=f"Your attendance status for {lesson.title} is {attendance.status}",
                notification_type='attendance'
            )
            
            # Log activity
            log_activity(
                session['user_id'],
                'Report Sent to Student',
                f'Sent attendance report to {student.full_name}',
                request.remote_addr
            )
            
        except Exception as e:
            app.logger.error(f"Failed to send to student {user.email}: {str(e)}")

# ===== STUDENT ATTENDANCE ROUTES =====


@app.route('/student/lessons')
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def student_lessons():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    # Get lessons for student's course and semester
    lessons = db.session.query(Lesson, Subject)\
        .join(Subject, Lesson.subject_id == Subject.id)\
        .filter(
            Subject.course == student.course,
            Subject.semester == student.semester
        )\
        .order_by(Lesson.date_time.desc())\
        .all()
    
    # Get student's attendance records
    attendance_records = {
        record.lesson_id: record 
        for record in Attendance.query.filter_by(student_id=student.id).all()
    }
    
    return render_template('student_lessons.html', 
                         lessons=lessons, 
                         student=student,
                         attendance_records=attendance_records)

@app.route('/student/scan-qr', methods=['GET', 'POST'])
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def scan_qr():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        qr_data = request.form.get('qr_data')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        if not qr_data:
            flash('No QR code data provided', 'error')
            return redirect(url_for('scan_qr'))
        
        # Verify QR code
        payload, error = verify_qr_payload(qr_data)
        if error:
            flash(f'Invalid QR code: {error}', 'error')
            return redirect(url_for('scan_qr'))
        
        lesson_id = payload['lesson_id']
        secret = payload['secret']
        
        # Get lesson and verify
        lesson = Lesson.query.get(lesson_id)
        if not lesson or lesson.qr_secret != secret:
            flash('Invalid lesson or QR code', 'error')
            return redirect(url_for('scan_qr'))
        
        # Check if lesson is active
        if lesson.status != 'active':
            flash('Lesson is not currently active for attendance', 'error')
            return redirect(url_for('scan_qr'))
        
        # Check if student is eligible
        if lesson.subject.course != student.course or lesson.subject.semester != student.semester:
            flash('You are not enrolled in this lesson', 'error')
            return redirect(url_for('scan_qr'))
        
        # Check if already scanned
        existing_attendance = Attendance.query.filter_by(
            lesson_id=lesson_id,
            student_id=student.id
        ).first()
        
        if existing_attendance:
            flash('You have already marked attendance for this lesson', 'warning')
            return redirect(url_for('student_lessons'))
        
        # Check geo-fencing if enabled
        if lesson.latitude and lesson.longitude and latitude and longitude:
            distance = calculate_distance(
                lesson.latitude, lesson.longitude,
                float(latitude), float(longitude)
            )
            
            if distance > lesson.geo_radius:
                flash(f'You are too far from the lesson location ({distance:.0f}m away)', 'error')
                return redirect(url_for('scan_qr'))
        
        # Check max scans limit
        if lesson.max_scans:
            current_scans = Attendance.query.filter_by(lesson_id=lesson_id).count()
            if current_scans >= lesson.max_scans:
                flash('Maximum attendance limit reached for this lesson', 'error')
                return redirect(url_for('scan_qr'))
        
        # Determine attendance status based on time
        now = datetime.utcnow()
        lesson_start = lesson.date_time
        grace_period = timedelta(minutes=10)  # 10 minutes grace period
        
        if now <= lesson_start + grace_period:
            status = 'present'
        else:
            status = 'late'
        
        # Create attendance record
        attendance = Attendance(
            lesson_id=lesson_id,
            student_id=student.id,
            status=status,
            scan_method='qr',
            ip_address=request.remote_addr,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            device_info=request.headers.get('User-Agent', '')
        )
        
        db.session.add(attendance)
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Attendance Scanned', 
                    f'Scanned QR for lesson: {lesson.title}', 
                    request.remote_addr)
        
        flash(f'Attendance marked successfully! Status: {status.title()}', 'success')
        return redirect(url_for('student_lessons'))
    
    return render_template('scan_qr.html', student=student)

@app.route('/student/enter-pin', methods=['GET', 'POST'])
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def enter_pin():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        pin = request.form.get('pin')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        if not pin:
            flash('Please enter the PIN', 'error')
            return redirect(url_for('enter_pin'))
        
        # Find lesson by PIN
        lesson = Lesson.query.filter_by(backup_pin=pin, status='active').first()
        if not lesson:
            flash('Invalid PIN or lesson not active', 'error')
            return redirect(url_for('enter_pin'))
        
        # Check if PIN is expired
        if lesson.qr_expiry < datetime.utcnow():
            flash('PIN has expired', 'error')
            return redirect(url_for('enter_pin'))
        
        # Rest of the validation logic is same as QR scan
        if lesson.subject.course != student.course or lesson.subject.semester != student.semester:
            flash('You are not enrolled in this lesson', 'error')
            return redirect(url_for('scan_qr'))
        
        # Check if already scanned
        existing_attendance = Attendance.query.filter_by(
            lesson_id=lesson.id,
            student_id=student.id
        ).first()
        
        if existing_attendance:
            flash('You have already marked attendance for this lesson', 'warning')
            return redirect(url_for('student_lessons'))
        
        # Check geo-fencing if enabled
        if lesson.latitude and lesson.longitude and latitude and longitude:
            distance = calculate_distance(
                lesson.latitude, lesson.longitude,
                float(latitude), float(longitude)
            )
            
            if distance > lesson.geo_radius:
                flash(f'You are too far from the lesson location ({distance:.0f}m away)', 'error')
                return redirect(url_for('scan_qr'))
        
        # Check max scans limit
        if lesson.max_scans:
            current_scans = Attendance.query.filter_by(lesson_id=lesson.id).count()
            if current_scans >= lesson.max_scans:
                flash('Maximum attendance limit reached for this lesson', 'error')
                return redirect(url_for('scan_qr'))
        
        # Determine attendance status based on time
        now = datetime.utcnow()
        lesson_start = lesson.date_time
        grace_period = timedelta(minutes=10)  # 10 minutes grace period
        
        if now <= lesson_start + grace_period:
            status = 'present'
        else:
            status = 'late'
        
        # Create attendance record
        attendance = Attendance(
            lesson_id=lesson.id,
            student_id=student.id,
            status=status,
            scan_method='qr',
            ip_address=request.remote_addr,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            device_info=request.headers.get('User-Agent', '')
        )
        
        db.session.add(attendance)
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Attendance Scanned', 
                    f'Scanned QR for lesson: {lesson.title}', 
                    request.remote_addr)
        
        
        # (Check eligibility, existing attendance, geo-fencing, etc.)
        
        # Similar validation as in scan_qr route...
        
        flash('Attendance marked successfully using PIN!', 'success')
        return redirect(url_for('student_lessons'))
    
    return render_template('enter_pin.html', student=student)

@app.route('/student/request-exception/<int:lesson_id>', methods=['GET', 'POST'])
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def request_exception(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        exception_type = request.form['exception_type']
        reason = request.form['reason']
        evidence_file = request.files.get('evidence')
        
        # Handle file upload
        filename = None
        if evidence_file and evidence_file.filename:
            filename = secure_filename(f"exception_{student.id}_{lesson_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{evidence_file.filename.rsplit('.', 1)[1].lower()}")
            evidence_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Create exception request
        exception = AttendanceException(
            lesson_id=lesson_id,
            student_id=student.id,
            exception_type=exception_type,
            reason=reason,
            evidence_file=filename
        )
        
        db.session.add(exception)
        db.session.commit()
        
        # Continuing from where the code left off...

        log_activity(session['user_id'], 'Exception Request', 
                    f'Requested attendance exception for {lesson.title}', 
                    request.remote_addr)
        
        flash('Exception request submitted successfully!', 'success')
        return redirect(url_for('student_lessons'))
    
    return render_template('request_exception.html', lesson=lesson, student=student)

@app.route('/student/attendance-history')
@login_required
@role_required(['student'])
@first_login_required
@student_approved_required
def student_attendance_history():
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    # Get all attendance records for this student
    attendance_records = db.session.query(Attendance, Lesson, Subject)\
        .join(Lesson, Attendance.lesson_id == Lesson.id)\
        .join(Subject, Lesson.subject_id == Subject.id)\
        .filter(Attendance.student_id == student.id)\
        .order_by(Lesson.date_time.desc())\
        .all()
    
    # Calculate statistics
    total_lessons = len(attendance_records)
    present_count = sum(1 for record, lesson, subject in attendance_records if record.status == 'present')
    late_count = sum(1 for record, lesson, subject in attendance_records if record.status == 'late')
    attendance_rate = (present_count + late_count) / total_lessons * 100 if total_lessons > 0 else 0
    
    return render_template('student_attendance_history.html', 
                         attendance_records=attendance_records,
                         student=student,
                         total_lessons=total_lessons,
                         present_count=present_count,
                         late_count=late_count,
                         attendance_rate=attendance_rate)
    
@app.route('/admin/lessons')
@login_required
@role_required(['admin'])
def admin_lessons():
    # Get all lessons across all teachers
    lessons = Lesson.query.order_by(Lesson.date_time.desc()).all()
    
    # Get all teachers sorted by their full_name from Teacher model
    teachers = Teacher.query.order_by(Teacher.full_name).all()
    
    return render_template('admin_lessons.html', lessons=lessons, teachers=teachers)

@app.route('/admin/lesson/<int:lesson_id>')
@login_required
@role_required(['admin'])
def admin_lesson_details(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    
    # Get attendance records
    attendance_records = db.session.query(Attendance, Student, User)\
        .join(Student, Attendance.student_id == Student.id)\
        .join(User, Student.user_id == User.id)\
        .filter(Attendance.lesson_id == lesson_id)\
        .order_by(Attendance.scan_time.asc())\
        .all()
    
    # Get expected students (enrolled in the course)
    expected_students = Student.query.filter_by(
        course=lesson.subject.course,
        semester=lesson.subject.semester,
        status='approved'
    ).all()
    
    # Calculate statistics
    total_expected = len(expected_students)
    total_present = len(attendance_records)
    attendance_rate = (total_present / total_expected * 100) if total_expected > 0 else 0
    
    return render_template('admin_lesson_details.html', 
                         lesson=lesson, 
                         attendance_records=attendance_records,
                         expected_students=expected_students,
                         total_expected=total_expected,
                         total_present=total_present,
                         attendance_rate=attendance_rate)

@app.route('/admin/lesson/<int:lesson_id>/update-status', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_update_lesson_status(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    new_status = request.form['status']
    
    if new_status not in ['active', 'paused', 'completed', 'cancelled']:
        flash('Invalid status', 'error')
        return redirect(url_for('admin_lesson_details', lesson_id=lesson_id))
    
    lesson.status = new_status
    db.session.commit()
    
    log_activity(session['user_id'], 'Lesson Status Updated', 
                f'Admin updated lesson {lesson.title} status to {new_status}', 
                request.remote_addr)
    
    flash('Lesson status updated successfully', 'success')
    return redirect(url_for('admin_lesson_details', lesson_id=lesson_id))

@app.route('/admin/lesson/<int:lesson_id>/manual-attendance', methods=['POST'])
@login_required
@role_required(['admin'])
def admin_manual_attendance(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    
    student_id = request.form['student_id']
    status = request.form['status']
    notes = request.form.get('notes', '')
    
    # Check if attendance already exists
    existing_attendance = Attendance.query.filter_by(
        lesson_id=lesson_id,
        student_id=student_id
    ).first()
    
    if existing_attendance:
        # Update existing record
        existing_attendance.status = status
        existing_attendance.scan_method = 'manual'
        existing_attendance.validation_notes = notes
        existing_attendance.verified_by = session['user_id']
        existing_attendance.updated_at = datetime.utcnow()
    else:
        # Create new record
        attendance = Attendance(
            lesson_id=lesson_id,
            student_id=student_id,
            status=status,
            scan_method='manual',
            validation_notes=notes,
            verified_by=session['user_id'],
            ip_address=request.remote_addr
        )
        db.session.add(attendance)
    
    db.session.commit()
    
    student = Student.query.get(student_id)
    log_activity(session['user_id'], 'Admin Manual Attendance', 
                f'Admin manually marked {student.full_name} as {status} for {lesson.title}', 
                request.remote_addr)
    
    flash('Attendance updated successfully!', 'success')
    return redirect(url_for('admin_lesson_details', lesson_id=lesson_id))

@app.route('/admin/lesson/<int:lesson_id>/export/<format>')
@login_required
@role_required(['admin'])
def admin_export_attendance(lesson_id, format):
    lesson = Lesson.query.get_or_404(lesson_id)
    
    # Get attendance data
    attendance_data = db.session.query(Attendance, Student, User)\
        .join(Student, Attendance.student_id == Student.id)\
        .join(User, Student.user_id == User.id)\
        .filter(Attendance.lesson_id == lesson_id)\
        .order_by(Student.roll_number.asc())\
        .all()
    
    if format == 'csv':
        return export_attendance_csv(lesson, attendance_data)
    elif format == 'excel':
        # Excel export not implemented, fallback to CSV
        flash('Excel export is not implemented. Downloading CSV instead.', 'warning')
        return export_attendance_csv(lesson, attendance_data)
    elif format == 'pdf':
        flash('PDF export is not implemented. Downloading CSV instead.', 'warning')
        return export_attendance_csv(lesson, attendance_data)
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('admin_lesson_details', lesson_id=lesson_id))


@app.route('/exams')
@login_required
@first_login_required
@student_approved_required
def student_exams():
    """Display available exams for students"""
    if session.get('role') != 'student':
        return redirect(url_for('dashboard'))
    
    student = Student.query.filter_by(user_id=session['user_id']).first()
    current_time = datetime.utcnow()
    
    # Get available exams for this student
    available_exams = []
    completed_exams = []
    upcoming_exams = []
    
    # Query exams based on student's course and semester
    exams = db.session.query(Exam).join(Subject).filter(
        Exam.status == 'active',
        or_(
            and_(
                Exam.target_courses.like(f'%"{student.course}"%'),
                Exam.target_semesters.like(f'%{student.semester}%')
            ),
            Exam.target_courses.is_(None)
        )
    ).all()
    
    for exam in exams:
        # Check if student has already attempted
        attempt = ExamAttempt.query.filter_by(
            exam_id=exam.id,
            student_id=student.id
        ).first()
        
        exam_info = {
            'exam': exam,
            'attempt': attempt,
            'can_attempt': False,
            'time_status': ''
        }
        
        if current_time < exam.start_time:
            exam_info['time_status'] = 'upcoming'
            upcoming_exams.append(exam_info)
        elif current_time > exam.end_time:
            exam_info['time_status'] = 'expired'
            completed_exams.append(exam_info)
        else:
            if not attempt:
                exam_info['can_attempt'] = True
                exam_info['time_status'] = 'available'
                available_exams.append(exam_info)
            elif attempt.status == 'completed' and attempt.attempt_number < exam.max_attempts:
                exam_info['can_attempt'] = True
                exam_info['time_status'] = 'retake_available'
                available_exams.append(exam_info)
            else:
                exam_info['time_status'] = 'completed'
                completed_exams.append(exam_info)
    
    return render_template('student_exams.html',
                         available_exams=available_exams,
                         completed_exams=completed_exams,
                         upcoming_exams=upcoming_exams,
                         student=student,
                         current_time=current_time)

@app.route('/exam/<int:exam_id>/details')
@login_required
@role_required(['student'])
@student_approved_required
def exam_details(exam_id):
    """Show exam details and requirements"""
    exam = Exam.query.get_or_404(exam_id)
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    # Check if student is eligible
    if not is_student_eligible_for_exam(student, exam):
        flash('You are not eligible for this exam', 'error')
        return redirect(url_for('student_exams'))
    
    # Get previous attempts
    attempts = ExamAttempt.query.filter_by(
        exam_id=exam_id,
        student_id=student.id
    ).order_by(ExamAttempt.attempt_number.desc()).all()
    
    return render_template('exam_details.html',
                         exam=exam,
                         student=student,
                         attempts=attempts,
                         current_time=datetime.utcnow())

@app.route('/exam/<int:exam_id>/start', methods=['GET', 'POST'])
@login_required
@role_required(['student'])
@student_approved_required
def start_exam(exam_id):
    """Start exam after verification"""
    exam = Exam.query.get_or_404(exam_id)
    student = Student.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        # Verify exam password if required
        if exam.exam_password:
            if request.form.get('exam_password') != exam.exam_password:
                flash('Invalid exam password', 'error')
                return render_template('start_exam.html', exam=exam)
        
        # Check time window
        current_time = datetime.utcnow()
        if current_time < exam.start_time or current_time > exam.end_time:
            flash('Exam is not available at this time', 'error')
            return redirect(url_for('student_exams'))
        
        # Check attempts
        previous_attempts = ExamAttempt.query.filter_by(
            exam_id=exam_id,
            student_id=student.id
        ).count()
        
        if previous_attempts >= exam.max_attempts:
            flash('You have exceeded the maximum number of attempts', 'error')
            return redirect(url_for('student_exams'))
        
        # Create new attempt
        attempt = ExamAttempt(
            exam_id=exam_id,
            student_id=student.id,
            attempt_number=previous_attempts + 1,
            browser_info=json.dumps({
                'user_agent': request.headers.get('User-Agent'),
                'platform': request.form.get('platform', 'unknown')
            }),
            ip_address=request.remote_addr
        )
        db.session.add(attempt)
        db.session.commit()
        
        # Log activity
        log_activity(session['user_id'], 'Exam Started', 
                    f'Started exam: {exam.title}', 
                    request.remote_addr)
        
        return redirect(url_for('take_exam', attempt_id=attempt.id))
    
    return render_template('start_exam.html', exam=exam, student=student)

@app.route('/exam/take/<int:attempt_id>')
@login_required
@role_required(['student'])
@student_approved_required
def take_exam(attempt_id):
    """Main exam taking interface"""
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status != 'in_progress':
        flash('This exam attempt is no longer active', 'error')
        return redirect(url_for('student_exams'))
    
    exam = attempt.exam
    
    # Check if time expired
    elapsed_time = (datetime.utcnow() - attempt.start_time).total_seconds()
    if elapsed_time > (exam.duration * 60):
        # Auto-submit exam
        submit_exam_automatically(attempt)
        flash('Exam time expired and has been automatically submitted', 'warning')
        return redirect(url_for('exam_result', attempt_id=attempt_id))
    
    # Get questions for this exam (randomized if enabled)
    questions = get_exam_questions(exam, attempt)
    
    # Get existing answers
    existing_answers = {
        answer.question_id: answer 
        for answer in attempt.answers
    }
    
    # Calculate time remaining
    time_remaining = max(0, (exam.duration * 60) - elapsed_time)
    
    return render_template('take_exam.html',
                         attempt=attempt,
                         exam=exam,
                         questions=questions,
                         existing_answers=existing_answers,
                         time_remaining=int(time_remaining),
                         current_question=1,
                         total_questions=len(questions))

@app.route('/exam/save-answer', methods=['POST'])
@login_required
@role_required(['student'])
def save_exam_answer():
    """Save or update answer for a question"""
    data = request.get_json()
    
    attempt_id = data.get('attempt_id')
    question_id = data.get('question_id')
    answer_data = data.get('answer_data')
    
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if attempt.status != 'in_progress':
        return jsonify({'success': False, 'error': 'Exam is not active'}), 400
    
    # Find or create answer
    answer = ExamAnswer.query.filter_by(
        attempt_id=attempt_id,
        question_id=question_id
    ).first()
    
    if not answer:
        question = QuestionBank.query.get(question_id)
        answer = ExamAnswer(
            attempt_id=attempt_id,
            question_id=question_id,
            max_marks=question.marks
        )
        db.session.add(answer)
    
    # Update answer based on question type
    question = QuestionBank.query.get(question_id)
    
    if question.question_type in ['mcq', 'true_false']:
        answer.selected_option = answer_data.get('selected_option')
        # Auto-grade if enabled
        if question.question_type == 'mcq' and attempt.exam.auto_grade_mcq:
            is_correct = answer.selected_option == question.correct_answer
            answer.is_correct = is_correct
            answer.marks_awarded = question.marks if is_correct else 0
        elif question.question_type == 'true_false' and attempt.exam.auto_grade_tf:
            is_correct = answer.selected_option == question.correct_answer
            answer.is_correct = is_correct
            answer.marks_awarded = question.marks if is_correct else 0
    
    elif question.question_type in ['fill_blank', 'essay']:
        answer.answer_text = answer_data.get('answer_text')
        # Auto-grade fill blanks if enabled and keywords provided
        if (question.question_type == 'fill_blank' and 
            attempt.exam.auto_grade_fillblank and 
            question.keywords):
            keywords = json.loads(question.keywords)
            student_answer = answer.answer_text.lower()
            matches = sum(1 for keyword in keywords if keyword.lower() in student_answer)
            score_percentage = matches / len(keywords) if keywords else 0
            answer.marks_awarded = question.marks * score_percentage
    
    answer.answered_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/exam/submit/<int:attempt_id>', methods=['POST'])
@login_required
@role_required(['student'])
def submit_exam(attempt_id):
    """Submit exam for grading"""
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status != 'in_progress':
        flash('Exam is not in progress', 'error')
        return redirect(url_for('student_exams'))
    
    # Mark as completed
    attempt.end_time = datetime.utcnow()
    attempt.status = 'completed'
    
    # Calculate scores
    calculate_exam_score(attempt)
    
    db.session.commit()
    
    # Log activity
    log_activity(session['user_id'], 'Exam Submitted', 
                f'Submitted exam: {attempt.exam.title}', 
                request.remote_addr)
    
    flash('Exam submitted successfully!', 'success')
    return redirect(url_for('exam_result', attempt_id=attempt_id))

@app.route('/exam/result/<int:attempt_id>')
@login_required
@role_required(['student'])
@student_approved_required
def exam_result(attempt_id):
    """Show exam results"""
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status == 'in_progress':
        flash('Exam is still in progress', 'error')
        return redirect(url_for('take_exam', attempt_id=attempt_id))
    
    # Get detailed results
    answers_with_questions = db.session.query(ExamAnswer, QuestionBank).join(
        QuestionBank, ExamAnswer.question_id == QuestionBank.id
    ).filter(ExamAnswer.attempt_id == attempt_id).all()
    
    # Calculate statistics
    total_questions = len(answers_with_questions)
    correct_answers = sum(1 for answer, _ in answers_with_questions if answer.is_correct)
    
    return render_template('exam_result.html',
                         attempt=attempt,
                         answers_with_questions=answers_with_questions,
                         total_questions=total_questions,
                         correct_answers=correct_answers,
                         show_answers=attempt.exam.show_results_immediately)

# HELPER FUNCTIONS

def is_student_eligible_for_exam(student, exam):
    """Check if student is eligible for the exam"""
    # Check course eligibility
    if exam.target_courses:
        target_courses = json.loads(exam.target_courses)
        if student.course not in target_courses:
            return False
    
    # Check semester eligibility
    if exam.target_semesters:
        target_semesters = json.loads(exam.target_semesters)
        if student.semester not in target_semesters:
            return False
    
    # Check specific students
    if exam.specific_students:
        specific_students = json.loads(exam.specific_students)
        if student.id not in specific_students:
            return False
    
    return True

def get_exam_questions(exam, attempt):
    """Get questions for exam, with randomization if enabled"""
    base_query = db.session.query(ExamQuestion, QuestionBank).join(
        QuestionBank, ExamQuestion.question_id == QuestionBank.id
    ).filter(ExamQuestion.exam_id == exam.id)
    
    if exam.randomize_questions:
        questions = base_query.order_by(func.random()).all()
    else:
        questions = base_query.order_by(ExamQuestion.question_order).all()
    
    # Randomize MCQ options if enabled
    if exam.randomize_options:
        for exam_question, question in questions:
            if question.question_type == 'mcq':
                options = [
                    ('A', question.option_a),
                    ('B', question.option_b),
                    ('C', question.option_c),
                    ('D', question.option_d)
                ]
                random.shuffle(options)
                # Store randomized options (you might want to save this mapping)
    
    return questions

def calculate_exam_score(attempt):
    """Calculate total score for exam attempt"""
    answers = ExamAnswer.query.filter_by(attempt_id=attempt.id).all()
    
    total_score = sum(answer.marks_awarded for answer in answers)
    max_possible = sum(answer.max_marks for answer in answers)
    
    if max_possible > 0:
        percentage = (total_score / max_possible) * 100
    else:
        percentage = 0
    
    # Determine grade and pass/fail
    grade, _ = calculate_grade_and_gpa(percentage)
    result_status = 'pass' if percentage >= attempt.exam.passing_marks else 'fail'
    
    # Update attempt
    attempt.total_score = total_score
    attempt.percentage = round(percentage, 2)
    attempt.grade = grade
    attempt.result_status = result_status
    
    # Check if all questions are auto-gradable
    questions_need_manual_grading = db.session.query(ExamAnswer).join(
        QuestionBank, ExamAnswer.question_id == QuestionBank.id
    ).filter(
        ExamAnswer.attempt_id == attempt.id,
        QuestionBank.question_type.in_(['essay', 'file_upload'])
    ).count()
    
    if questions_need_manual_grading == 0:
        attempt.auto_graded = True
    
    db.session.commit()

def submit_exam_automatically(attempt):
    """Auto-submit exam when time expires"""
    attempt.end_time = datetime.utcnow()
    attempt.status = 'timed_out'
    calculate_exam_score(attempt)
    db.session.commit()

# TEACHER EXAM MANAGEMENT ROUTES

@app.route('/teacher/exams')
@login_required
@role_required(['teacher'])
@first_login_required
def teacher_exams():
    """List exams created by teacher"""
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    
    exams = db.session.query(Exam).join(Subject).filter(
        Subject.teacher_id == teacher.id
    ).order_by(Exam.created_at.desc()).all()
    
    return render_template('teacher_exams.html', exams=exams, teacher=teacher)

@app.route('/teacher/exam/create', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def create_exam():
    """Create new exam"""
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    if request.method == 'POST':
        # Create exam
        exam = Exam(
            title=request.form['title'],
            description=request.form.get('description'),
            subject_id=request.form['subject_id'],
            start_time=datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M'),
            end_time=datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M'),
            duration=int(request.form['duration']),
            total_marks=float(request.form.get('total_marks', 100)),
            passing_marks=float(request.form.get('passing_marks', 40)),
            max_attempts=int(request.form.get('max_attempts', 1)),
            randomize_questions=bool(request.form.get('randomize_questions')),
            randomize_options=bool(request.form.get('randomize_options')),
            show_results_immediately=bool(request.form.get('show_results_immediately')),
            allow_backtrack=bool(request.form.get('allow_backtrack')),
            enable_proctoring=bool(request.form.get('enable_proctoring')),
            webcam_required=bool(request.form.get('webcam_required')),
            browser_lockdown=bool(request.form.get('browser_lockdown')),
            exam_password=request.form.get('exam_password'),
            created_by=session['user_id']
        )
        
        # Set targeting
        target_courses = request.form.getlist('target_courses')
        target_semesters = [int(s) for s in request.form.getlist('target_semesters')]
        
        if target_courses:
            exam.target_courses = json.dumps(target_courses)
        if target_semesters:
            exam.target_semesters = json.dumps(target_semesters)
        
        db.session.add(exam)
        db.session.commit()
        
        flash('Exam created successfully!', 'success')
        return redirect(url_for('add_exam_questions', exam_id=exam.id))
    
    return render_template('create_exam.html', subjects=subjects, courses=COURSES)

@app.route('/teacher/exam/<int:exam_id>/questions', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
def add_exam_questions(exam_id):
    """Add questions to exam"""
    exam = Exam.query.get_or_404(exam_id)
    
    # Verify ownership
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    if exam.subject.teacher_id != teacher.id:
        abort(403)
    
    if request.method == 'POST':
        # Add question from question bank
        question_ids = request.form.getlist('question_ids')
        for i, question_id in enumerate(question_ids):
            question = QuestionBank.query.get(question_id)
            exam_question = ExamQuestion(
                exam_id=exam_id,
                question_id=question_id,
                question_order=i + 1,
                marks=question.marks
            )
            db.session.add(exam_question)
        
        db.session.commit()
        flash('Questions added to exam successfully!', 'success')
        return redirect(url_for('teacher_exams'))
    
    # Get available questions from question bank
    available_questions = QuestionBank.query.filter_by(
        subject_id=exam.subject_id,
        is_active=True
    ).all()
    
    # Get already added questions
    added_questions = db.session.query(ExamQuestion, QuestionBank).join(
        QuestionBank, ExamQuestion.question_id == QuestionBank.id
    ).filter(ExamQuestion.exam_id == exam_id).all()
    
    return render_template('add_exam_questions.html',
                         exam=exam,
                         available_questions=available_questions,
                         added_questions=added_questions)

@app.route('/teacher/question-bank')
@login_required
@role_required(['teacher'])
@first_login_required
def question_bank():
    """Manage question bank"""
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    # Get questions created by this teacher
    questions = QuestionBank.query.filter_by(
        created_by=session['user_id'],
        is_active=True
    ).order_by(QuestionBank.created_at.desc()).all()
    
    return render_template('question_bank.html',
                         questions=questions,
                         subjects=subjects,
                         teacher=teacher)

@app.route('/teacher/question/create', methods=['GET', 'POST'])
@login_required
@role_required(['teacher'])
@first_login_required
def create_question():
    """Create new question"""
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    subjects = Subject.query.filter_by(teacher_id=teacher.id, is_active=True).all()
    
    if request.method == 'POST':
        question = QuestionBank(
            question_text=request.form['question_text'],
            question_type=request.form['question_type'],
            subject_id=request.form['subject_id'],
            difficulty_level=request.form.get('difficulty_level', 'medium'),
            marks=float(request.form.get('marks', 1.0)),
            category=request.form.get('category'),
            created_by=session['user_id']
        )
        
        # Handle question type specific fields
        if question.question_type == 'mcq':
            question.option_a = request.form['option_a']
            question.option_b = request.form['option_b']
            question.option_c = request.form['option_c']
            question.option_d = request.form['option_d']
            question.correct_answer = request.form['correct_answer']
        
        elif question.question_type == 'true_false':
            question.correct_answer = request.form['correct_answer']
        
        elif question.question_type in ['fill_blank', 'essay']:
            question.model_answer = request.form.get('model_answer')
            keywords = request.form.get('keywords', '').split(',')
            if keywords and keywords[0]:  # Check if keywords exist
                question.keywords = json.dumps([k.strip() for k in keywords])
        
        db.session.add(question)
        db.session.commit()
        
        log_activity(session['user_id'], 'Question Created',
                    f'Created {question.question_type} question for {question.subject.subject_name}',
                    request.remote_addr)
        
        flash('Question created successfully!', 'success')
        return redirect(url_for('question_bank'))
    
    return render_template('create_question.html', subjects=subjects)

@app.route('/teacher/exam/<int:exam_id>/results')
@login_required
@role_required(['teacher'])
def exam_results_overview(exam_id):
    """View exam results and analytics"""
    exam = Exam.query.get_or_404(exam_id)
    
    # Verify ownership
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    if exam.subject.teacher_id != teacher.id:
        abort(403)
    
    # Get all attempts for this exam
    attempts = db.session.query(ExamAttempt, Student).join(
        Student, ExamAttempt.student_id == Student.id
    ).filter(
        ExamAttempt.exam_id == exam_id,
        ExamAttempt.status.in_(['completed', 'timed_out'])
    ).order_by(ExamAttempt.total_score.desc()).all()
    
    # Calculate statistics
    if attempts:
        scores = [attempt.total_score for attempt, _ in attempts]
        avg_score = sum(scores) / len(scores)
        highest_score = max(scores)
        lowest_score = min(scores)
        pass_count = sum(1 for attempt, _ in attempts if attempt.result_status == 'pass')
        pass_rate = (pass_count / len(attempts)) * 100
    else:
        avg_score = highest_score = lowest_score = pass_rate = 0
    
    # Grade distribution
    grade_distribution = {}
    for attempt, _ in attempts:
        grade = attempt.grade or 'N/A'
        grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
    
    return render_template('exam_results_overview.html',
                         exam=exam,
                         attempts=attempts,
                         avg_score=round(avg_score, 2),
                         highest_score=highest_score,
                         lowest_score=lowest_score,
                         pass_rate=round(pass_rate, 2),
                         grade_distribution=grade_distribution)

@app.route('/teacher/exam/<int:exam_id>/grade')
@login_required
@role_required(['teacher'])
def grade_exam(exam_id):
    """Grade essay and subjective questions"""
    exam = Exam.query.get_or_404(exam_id)
    
    # Verify ownership
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    if exam.subject.teacher_id != teacher.id:
        abort(403)
    
    # Get answers that need manual grading
    pending_answers = db.session.query(ExamAnswer, QuestionBank, Student).join(
        QuestionBank, ExamAnswer.question_id == QuestionBank.id
    ).join(
        ExamAttempt, ExamAnswer.attempt_id == ExamAttempt.id
    ).join(
        Student, ExamAttempt.student_id == Student.id
    ).filter(
        ExamAttempt.exam_id == exam_id,
        QuestionBank.question_type.in_(['essay', 'file_upload']),
        ExamAnswer.graded_by.is_(None)
    ).all()
    
    return render_template('grade_exam.html',
                         exam=exam,
                         pending_answers=pending_answers)

@app.route('/teacher/grade-answer/<int:answer_id>', methods=['POST'])
@login_required
@role_required(['teacher'])
def grade_answer(answer_id):
    """Grade individual answer"""
    answer = ExamAnswer.query.get_or_404(answer_id)
    
    # Verify ownership
    teacher = Teacher.query.filter_by(user_id=session['user_id']).first()
    exam = answer.attempt.exam
    if exam.subject.teacher_id != teacher.id:
        abort(403)
    
    # Update grade
    manual_score = float(request.form['manual_score'])
    feedback = request.form.get('feedback', '')
    
    if manual_score > answer.max_marks:
        flash('Score cannot exceed maximum marks', 'error')
        return redirect(url_for('grade_exam', exam_id=exam.id))
    
    answer.manual_score = manual_score
    answer.marks_awarded = manual_score
    answer.feedback = feedback
    answer.graded_by = session['user_id']
    answer.graded_at = datetime.utcnow()
    
    # Check if all answers for this attempt are graded
    ungraded_count = ExamAnswer.query.join(QuestionBank).filter(
        ExamAnswer.attempt_id == answer.attempt_id,
        QuestionBank.question_type.in_(['essay', 'file_upload']),
        ExamAnswer.graded_by.is_(None)
    ).count()
    
    if ungraded_count == 0:
        # Recalculate total score
        calculate_exam_score(answer.attempt)
        answer.attempt.manually_graded = True
    
    db.session.commit()
    
    flash('Answer graded successfully!', 'success')
    return redirect(url_for('grade_exam', exam_id=exam.id))

# ACADEMIC EXAM OVERSIGHT

@app.route('/academic/exams')
@login_required
@role_required(['academic'])
@first_login_required
def academic_exam_overview():
    """Academic oversight of all exams"""
    # Get all exams in the system
    exams = db.session.query(Exam, Subject, Teacher).join(
        Subject, Exam.subject_id == Subject.id
    ).join(
        Teacher, Subject.teacher_id == Teacher.id
    ).order_by(Exam.created_at.desc()).all()
    
    # Get exam statistics
    total_exams = len(exams)
    active_exams = sum(1 for exam, _, _ in exams if exam.status == 'active')
    completed_exams = sum(1 for exam, _, _ in exams if exam.status == 'completed')
    
    return render_template('academic_exam_overview.html',
                         exams=exams,
                         total_exams=total_exams,
                         active_exams=active_exams,
                         completed_exams=completed_exams)

@app.route('/academic/exam/<int:exam_id>/monitor')
@login_required
@role_required(['academic'])
def monitor_exam(exam_id):
    """Monitor ongoing exam"""
    exam = Exam.query.get_or_404(exam_id)
    
    # Get active attempts
    active_attempts = db.session.query(ExamAttempt, Student).join(
        Student, ExamAttempt.student_id == Student.id
    ).filter(
        ExamAttempt.exam_id == exam_id,
        ExamAttempt.status == 'in_progress'
    ).all()
    
    # Get proctoring violations
    violations = db.session.query(ProctoringEvent, Student).join(
        ExamAttempt, ProctoringEvent.attempt_id == ExamAttempt.id
    ).join(
        Student, ExamAttempt.student_id == Student.id
    ).filter(
        ExamAttempt.exam_id == exam_id,
        ProctoringEvent.severity.in_(['high', 'critical'])
    ).order_by(ProctoringEvent.timestamp.desc()).all()
    
    return render_template('monitor_exam.html',
                         exam=exam,
                         active_attempts=active_attempts,
                         violations=violations)

# API ROUTES FOR EXAM FUNCTIONALITY

@app.route('/api/exam/<int:attempt_id>/time-remaining')
@login_required
def get_time_remaining(attempt_id):
    """Get remaining time for exam attempt"""
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        return jsonify({'error': 'Access denied'}), 403
    
    if attempt.status != 'in_progress':
        return jsonify({'time_remaining': 0, 'status': attempt.status})
    
    elapsed_time = (datetime.utcnow() - attempt.start_time).total_seconds()
    time_remaining = max(0, (attempt.exam.duration * 60) - elapsed_time)
    
    return jsonify({
        'time_remaining': int(time_remaining),
        'status': attempt.status
    })

@app.route('/api/exam/proctoring-event', methods=['POST'])
@login_required
def log_proctoring_event():
    """Log proctoring violation"""
    data = request.get_json()
    
    attempt_id = data.get('attempt_id')
    event_type = data.get('event_type')
    event_data = data.get('event_data', {})
    severity = data.get('severity', 'low')
    
    attempt = ExamAttempt.query.get_or_404(attempt_id)
    
    # Verify ownership
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if attempt.student_id != student.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Create proctoring event
    event = ProctoringEvent(
        attempt_id=attempt_id,
        event_type=event_type,
        event_data=json.dumps(event_data),
        severity=severity
    )
    db.session.add(event)
    
    # Update violation count
    attempt.violation_count += 1
    
    # Auto-submit if too many critical violations
    if severity == 'critical' and attempt.violation_count >= 3:
        attempt.status = 'completed'
        attempt.end_time = datetime.utcnow()
        calculate_exam_score(attempt)
        
        db.session.commit()
        return jsonify({
            'success': True,
            'action': 'exam_terminated',
            'message': 'Exam terminated due to multiple violations'
        })
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/exam/<int:exam_id>/questions')
@login_required
def get_exam_questions_api(exam_id):
    """Get exam questions for AJAX loading"""
    exam = Exam.query.get_or_404(exam_id)
    
    # Verify student access
    student = Student.query.filter_by(user_id=session['user_id']).first()
    if not is_student_eligible_for_exam(student, exam):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get active attempt
    attempt = ExamAttempt.query.filter_by(
        exam_id=exam_id,
        student_id=student.id,
        status='in_progress'
    ).first()
    
    if not attempt:
        return jsonify({'error': 'No active attempt'}), 400
    
    questions = get_exam_questions(exam, attempt)
    
    questions_data = []
    for exam_question, question in questions:
        question_data = {
            'id': question.id,
            'text': question.question_text,
            'type': question.question_type,
            'marks': question.marks,
            'order': exam_question.question_order
        }
        
        if question.question_type == 'mcq':
            question_data['options'] = {
                'A': question.option_a,
                'B': question.option_b,
                'C': question.option_c,
                'D': question.option_d
            }
        
        questions_data.append(question_data)
    
    return jsonify({'questions': questions_data})


@app.errorhandler(500)
def internal_error(e):
    print(f"error occured {str(e)}")
    return redirect("500"),500
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    if os.environ.get('FLASK_ENV') == 'production':
        socketio.run(app, host='0.0.0.0', port=port)
    else:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
