from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

#TODO include css in html

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def create_connection():
    return sqlite3.connect('users.db')

def create_user_table(conn):
    sql_create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    """

    try:
        cursor = conn.cursor()
        cursor.execute(sql_create_users_table)
        conn.commit()
    except sqlite3.Error as e:
        print(e)

def insert_user(conn, username, password):
    sql_insert_user = """
    INSERT INTO users (username, password) VALUES (?, ?);
    """

    try:
        cursor = conn.cursor()
        cursor.execute(sql_insert_user, (username, generate_password_hash(password)))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(e)
        return False

def get_user(conn, username):
    sql_get_user = """
    SELECT * FROM users WHERE username = ?;
    """

    cursor = conn.cursor()
    cursor.execute(sql_get_user, (username,))
    return cursor.fetchone()

def is_logged_in():
    return 'username' in session

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = create_connection()
        user = get_user(conn, username)
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            error = "Incorrect username or password. Please try again."

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = create_connection()
        if insert_user(conn, username, password):
            conn.close()
            return redirect(url_for('login'))  # Redirect to login after registration
        else:
            error = "Failed to register user. Please try again."
            conn.close()

    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    if is_logged_in():
        return f"Welcome, {session['username']}! You are logged in."
    else:
        return redirect(url_for('login'))
    
@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('dashboard.html')

def create_message_table(conn):
    sql_create_messages_table = """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """

    try:
        cursor = conn.cursor()
        cursor.execute(sql_create_messages_table)
        conn.commit()
    except sqlite3.Error as e:
        print(e)

def insert_message(conn, sender, recipient, message):
    sql_insert_message = """
    INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?);
    """

    try:
        cursor = conn.cursor()
        cursor.execute(sql_insert_message, (sender, recipient, message))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(e)
        return False

# Add a new route for retrieving messages for a specific recipient
@app.route('/get_messages/<recipient>')
def get_messages(recipient):
    if is_logged_in():
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)", (session['username'], recipient, recipient, session['username']))
        messages = cursor.fetchall()
        conn.close()

        formatted_messages = []
        for message in messages:
            formatted_message = f"{message[1]} to {message[2]}: {message[3]} ({message[4]})"
            formatted_messages.append(formatted_message)

        return '<br>'.join(formatted_messages)
    else:
        return 'Unauthorized', 401  # Return unauthorized status code if user is not logged in

@app.route('/send_message', methods=['POST'])
def send_message():
    if is_logged_in():
        sender = session['username']
        recipient = request.form.get('recipient')
        message = request.form.get('message')
        
        conn = create_connection()
        if insert_message(conn, sender, recipient, message):
            conn.close()
            return '', 204  # Return empty response with HTTP status code 204 (No Content)
        else:
            conn.close()
            return 'Failed to send message', 500  # Return error message with HTTP status code 500 (Internal Server Error)
    
@app.route('/get_chats')
def get_chats():
    if is_logged_in():
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT recipient FROM messages WHERE sender=?", (session['username'],))
        chats = cursor.fetchall()
        conn.close()

        formatted_chats = []
        for chat in chats:
            formatted_chats.append(f'<div class="chat" data-recipient="{chat[0]}">{chat[0]}</div>')

        return ''.join(formatted_chats)
    else:
        return 'Unauthorized', 401  # Return unauthorized status code if user is not logged in

if __name__ == '__main__':
    conn = create_connection()
    create_user_table(conn)
    create_message_table(conn)
    conn.close()
    app.run('0.0.0.0', port=5000)