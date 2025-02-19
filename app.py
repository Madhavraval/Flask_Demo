from flask import Flask, render_template, request, redirect, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Madhav@123'
app.config['MYSQL_DB'] = 'flask_crud'
mysql = MySQL(app)

# Admin Credentials
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin123"

# Home Page
@app.route('/',methods=['GET', 'POST'])
def index():
    return render_template('index.html')

# Register User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, phone, dob, password) VALUES (%s, %s, %s, %s, %s)", 
                       (name, email, phone, dob, password))
        mysql.connection.commit()
        cursor.close()

        flash('Registration successful! Please login.', 'success')
        return redirect('/login')

    return render_template('register.html')

# Login User & Admin
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin_dashboard')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[5], password):
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

# User Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()

    return render_template('dashboard_user.html', user=user)

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()

    return render_template('dashboard_admin.html', users=users)

# Add User (Admin)
@app.route('/admin_add_user', methods=['POST'])
def admin_add_user():
    if 'admin' not in session:
        return redirect('/login')

    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    dob = request.form['dob']
    password = generate_password_hash(request.form['password'])

    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO users (name, email, phone, dob, password) VALUES (%s, %s, %s, %s, %s)", 
                   (name, email, phone, dob, password))
    mysql.connection.commit()
    cursor.close()

    flash('New user added successfully!', 'success')
    return redirect('/admin_dashboard')

# Update User Profile
@app.route('/update', methods=['GET', 'POST'])
def update():
    # if 'user_id' not in session:
    #     return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        dob = request.form['dob']

        cursor.execute("UPDATE users SET name = %s, phone = %s, dob = %s WHERE id = %s",
                       (name, phone, dob, session['user_id']))
        mysql.connection.commit()
        cursor.close()

        flash('Profile updated successfully!', 'success')
        return redirect('/dashboard')

    return render_template('update.html', user=user)

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('admin', None)
    flash('Logged out successfully.', 'info')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
