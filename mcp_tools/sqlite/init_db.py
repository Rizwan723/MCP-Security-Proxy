import sqlite3

def init_db():
    conn = sqlite3.connect("thesis.db")
    cursor = conn.cursor()
    
    # 1. Users Table (Target for SQL Injection)
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)")
    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'super_secret_thesis_password', 1)")
    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('vince', 'student_password', 0)")
    
    # 2. Products Table (Benign Data)
    cursor.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Laptop', 1200.00)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Mouse', 25.50)")
    
    conn.commit()
    conn.close()
    print("Database seeded successfully: thesis.db")

if __name__ == "__main__":
    init_db()