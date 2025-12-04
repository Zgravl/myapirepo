from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps
import jwt, datetime
import sqlite3

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

ENCRYPTION_KEY = "secretkey"

import os
import hashlib

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

def hash_password(password):
    """Hash a password using SHA-256 with a salt"""
    salt = os.environ.get('PASSWORD_SALT', 'default_salt_change_in_production')
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Connects to database
def get_db_connection():
    conn = sqlite3.connect('mydatabase.db')
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Ensure tables exist and a UNIQUE index on student emails prevents
    # check-then-insert races by enforcing uniqueness at the DB level.
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY,
                name TEXT,
                type TEXT,
                grade INTEGER,
                email TEXT,
                password TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS staff (
                id INTEGER PRIMARY KEY,
                name TEXT,
                type TEXT,
                email TEXT,
                password TEXT
            )
        ''')
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_students_email ON students(email)")
    except sqlite3.Error:
        # ignore schema creation errors here; normal operations will raise later
        pass
    return conn

# SQL Security Improvements 
# 1. All SQL queries use parameterized queries
# 2. Input validation is performed before executing queries
# 3. Passwords are hashed before storing or comparing

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, ENCRYPTION_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        request.user = data
        return f(*args, **kwargs)
    return decorated

# Gets student ID from user and queries the database for matching student.
@app.route('/retrieve', methods=['GET'])
@token_required
@limiter.limit("5 per minute")
def retrieveGrades():
    user = request.user
    if user["role"] != "staff":
        return jsonify({"error": "Access denied: staff only"}), 403
    
    studentID = request.args.get("studentId", "").strip()
    if not studentID.isdigit():
        return jsonify({"error": "Invalid student ID"}), 400
    
    conn = get_db_connection()
    try:

        students = conn.execute("SELECT * FROM students WHERE id = ?", (studentID,)).fetchall()
        return jsonify({"results": [dict(row) for row in students]})
    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@app.route('/login', methods=['GET'])
@limiter.limit("10 per minute")
def Login():
    # Get email and password from arguments
    email = request.args.get("email", "").strip()
    password = request.args.get("password", "").strip()
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    # Hash the password before comparing
    hashed_password = hash_password(password)
    
    # Queries database
    conn = get_db_connection()
    try:
        all = conn.execute("""
            SELECT name, email, password, type 
            FROM (
                SELECT name, email, password, type FROM students WHERE email = ? AND password = ?
                UNION
                SELECT name, email, password, type FROM staff WHERE email = ? AND password = ?
            )""", (email, hashed_password, email, hashed_password)).fetchall()
        
        students = conn.execute("""
            SELECT id, name, email, grade 
            FROM students 
            WHERE email = ? AND password = ?""", 
            (email, hashed_password)).fetchall()
        
        if not all and not students:
            return jsonify({"error": "Invalid credentials"}), 401
        
        user = dict(all[0])
        
        # Generate JWT token
        token = jwt.encode({
            "email": user["email"],
            "role": user["type"],
            "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        }, ENCRYPTION_KEY, algorithm="HS256")
        
        if students:
            return jsonify({
                "results": [dict(row) for row in all],
                "info": [dict(row) for row in students],
                "token": token
            })
        return jsonify({
            "results": [dict(row) for row in all],
            "token": token
        })
        
    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@app.route('/add', methods=['POST'])
@token_required
@limiter.limit("5 per minute")
def AddStudents():
    user = request.user
    if user["role"] != "staff":
        return jsonify({"error": "Access denied: staff only"}), 403
    
    # Get all info for new student
    data = request.get_json()
    studentName = data.get("studentName", "").strip()
    studentEmail = data.get("studentEmail", "").strip()
    studentPass = data.get("studentPass", "").strip()
    studentGrade = data.get("studentGrade", "").strip()
    
    
    if not all([studentName, studentEmail, studentPass, studentGrade]):
        return jsonify({"error": "All fields are required"}), 400
    if not studentGrade.isdigit():
        return jsonify({"error": "Invalid grade format"}), 400
    
    hashed_password = hash_password(studentPass)
    
    conn = get_db_connection()
    try:
        # Insert directly and rely on the UNIQUE index to prevent duplicates.
        cursor = conn.execute("""
            INSERT INTO students (name, type, grade, email, password) 
            VALUES (?, 'student', ?, ?, ?)""", 
            (studentName, studentGrade, studentEmail, hashed_password))

        conn.commit()

        new_id = cursor.lastrowid
        return jsonify({
            "message": "success",
            "ID": [{"id": new_id}]
        })

    except sqlite3.IntegrityError:
        # UNIQUE constraint violation -> email already registered
        conn.rollback()
        return jsonify({"error": "Email already registered"}), 409
    except sqlite3.Error:
        conn.rollback()
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@app.route('/update', methods=['POST'])
@token_required
@limiter.limit("5 per minute")
def UpdateGrade():
    user = request.user
    if user["role"] != "staff":
        return jsonify({"error": "Access denied: staff only"}), 403
    
    # Get all info for new student
    data = request.get_json()
    studentId = data.get("studentId")
    studentGrade = data.get("newGrade", "").strip()
    
    if not all([studentId, studentGrade]):
        return jsonify({"error": "All fields are required"}), 400
    if not studentGrade.isdigit():
        return jsonify({"error": "Invalid grade format"}), 400
    
    
    conn = get_db_connection()
    try:
        cursor = conn.execute("""
            UPDATE students
            SET grade = (?) 
            WHERE id = (?)""", 
            (studentGrade, studentId))
        
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Student not found"}), 404
        
        return jsonify({
            "message": "success",
        })
        
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
