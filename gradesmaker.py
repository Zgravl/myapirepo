from GradesAccess import hash_password
import sqlite3

conn = sqlite3.connect('mydatabase.db')
conn.execute('CREATE TABLE students (id INTEGER PRIMARY KEY, name TEXT, type TEXT, grade INTEGER, email TEXT, password TEXT)')
conn.execute(f"INSERT INTO students (name, type, grade, email, password) VALUES ('Alice', 'student', 78, 'alice@gmail.com', '{hash_password("mypass")}')")
conn.execute(f"INSERT INTO students (name, type, grade, email, password) VALUES ('Bob', 'student', 84, 'bob@gmail.com', '{hash_password("mypass2")}')")

conn.execute('CREATE TABLE staff (id INTEGER PRIMARY KEY, name TEXT, type TEXT, email TEXT, password TEXT)')
conn.execute(f"INSERT INTO staff (name, type, email, password) VALUES ('Jane', 'staff', 'jane@gmail.com', '{hash_password("mypass3")}')")
conn.execute(f"INSERT INTO staff (name, type, email, password) VALUES ('John', 'staff', 'john@gmail.com', '{hash_password("mypass4")}')")
conn.commit()
conn.close()
