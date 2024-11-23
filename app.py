from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL

app = Flask(__name__)
mysql = MySQL(app)
app.secret_key = 'your-secret-key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'register_users'



@app.route('/')
def home():
    email = session.get('email')
    return render_template('home.html', userEmail=email)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        pwd = request.form.get('password')
        
        if username and email and pwd:
            hashed_pwd = generate_password_hash(pwd)
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_pwd))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Please fill in all fields.")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        pwd = request.form.get('password')
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT username, email, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if user and check_password_hash(user[2], pwd):
            session['username'] = user[0]
            session['email'] = user[1]
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid email or password')
   
    return render_template('login.html')

@app.route('/reset', methods=['GET', 'POST'])
def ResetPassword():
    if request.method == 'POST':
        email = request.form.get("email")
        newPassword = request.form.get('newPassword')
        if email and newPassword:
            try:
                hashed_npwd = generate_password_hash(newPassword)
                with mysql.connection.cursor() as cur:
                    cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_npwd, email))
                    mysql.connection.commit()
            except mysql.connector.Error as err:
                print(f"Помилка: {err}")
                mysql.connection.rollback()
            return redirect(url_for('login'))
        else:
            return render_template('reset.html', error='Будь ласка, заповніть усі поля')
    return render_template('reset.html')


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)