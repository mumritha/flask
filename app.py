from flask import Flask, render_template, request, redirect, session
import re
import mysql.connector
import socket
from datetime import datetime
from tabulate import tabulate

app = Flask(__name__)
app.secret_key = "secret"

# Configure your MySQL database connection details
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'registration',
    'port': '3306'
}

# Define a function to validate email format
def is_valid_email(email):
    return re.match(r"[a-z0-9_\-\.]+[@][a-z]+[\.][a-z]{2,3}", email)

@app.route('/')
def student():
    return render_template('neew.html')

@app.route('/home')
def neew():
    if 'email' in session:
        email = session['email']
        con = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database'],
            port=db_config['port']
        )
        cursor = con.cursor()
        user_query = 'SELECT * FROM reg WHERE email=%s'
        cursor.execute(user_query, (email,))
        user_row = cursor.fetchone()
        if user_row:
            headers = ['NAME', 'NUMBER', 'EMAIL']
            data = [[user_row[1], user_row[2], user_row[3]]]
            table = tabulate(data, headers=headers, tablefmt="html")
            return render_template('home.html', email=email, table=table)
    return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    # Retrieve form data
    name = request.form['username']
    mobile = request.form['mobilenumber']
    email = request.form['email']
    password = request.form['password']
    conformpassword = request.form['conformpassword']

    # Perform form validation
    errors = []

    if not name:
        errors.append("Username is required.")

    if not mobile:
        errors.append("Mobile number is required.")

    if not email:
        errors.append("Email is required.")
    else:
        if not is_valid_email(email):
            errors.append("Invalid email address.")

    if not password:
        errors.append("Password is required.")
    elif len(password) < 8 or len(password) > 16:
        errors.append("Password length must be between 8 and 16 characters.")
    elif not re.search("[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    elif not re.search("[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    elif not re.search("[0-9]", password):
        errors.append("Password must contain at least one numeric value.")
    elif not re.search(r"[@#$%^&+=]", password):
        errors.append("Password must contain at least one special character.")
    elif re.search(r"\s", password):
        errors.append("Password must not contain any whitespace characters.")

    if not conformpassword:
        errors.append("Confirm password is required.")
    elif password != conformpassword:
        errors.append("Password and confirm password do not match.")

    if errors:
        return render_template('error.html', errors=errors)
    else:
        # Insert data into the database
        try:
            con = mysql.connector.connect(
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['password'],
                database=db_config['database'],
                port=db_config['port']
            )
            cursor = con.cursor()
            sql = "INSERT INTO reg (name, mobilenumber, email, password) VALUES (%s, %s, %s, %s)"
            values = (name, mobile, email, password)
            cursor.execute(sql, values)
            con.commit()
            cursor.close()
            con.close()
            return redirect('/')
        except mysql.connector.Error as error:
            errors.append("Failed to insert data into the database.")
            return render_template('error.html', errors=errors)

@app.route('/login', methods=['POST'])
def login():
    email = request.form['lemail']
    password = request.form['lpassword']
    ip_address = socket.gethostbyname(socket.gethostname())
    device_name = socket.gethostname()

    try:
        con = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database'],
            port=db_config['port']
        )
        cursor = con.cursor()
        query = 'SELECT * FROM reg WHERE email=%s AND password=%s'
        cursor.execute(query, (email, password))
        row = cursor.fetchone()
        if row:
            session['logged_in'] = True
            session['email'] = email
            sql = "INSERT INTO log (email, password, ip_address, device_name) VALUES (%s, %s, %s, %s)"
            values = (email, password, ip_address, device_name)
            cursor.execute(sql, values)
            con.commit()
            user_query = 'SELECT * FROM reg WHERE email=%s'
            cursor.execute(user_query, (email,))
            user_row = cursor.fetchone()
            user = {
                'name': user_row[1],
                'mobilenumber': user_row[2],
                'email': user_row[3]
    }

            cursor.close()
            con.close()
            
            return render_template('loggedin.html', email=email, user=user)
        else:
            return render_template('error.html', errors=["Invalid email or password."])
    except mysql.connector.Error as error:
        return render_template('error.html', errors=["Failed to connect to the database."])
    

@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('logged_in', None)

    con = mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database'],
        port=db_config['port'])
    cur = con.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = "UPDATE log SET logout_datetime = %s WHERE email = (SELECT email FROM log WHERE logout_datetime IS NULL LIMIT 1)"
    values = (timestamp,)
    cur.execute(sql, values)
    con.commit()
    cur.close()
    con.close()

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
