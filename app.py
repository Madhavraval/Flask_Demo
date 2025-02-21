from flask import Flask, render_template, request, redirect, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Varun@@18+'
app.config['MYSQL_DB'] = 'flask_crud'
mysql = MySQL(app)

# Admin Credentials
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")  # Hashed admin password

# Home Page
@app.route('/', methods=['GET', 'POST'])
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
        password = generate_password_hash(request.form['password'])  # Hashing password

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

        if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin'] = True
            session['user_email'] = email  # Store email in session
            flash('Admin login successful!', 'success')
            return redirect('/admin_dashboard')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[5], password):
            session['user_id'] = user[0]
            session['user_email'] = user[2]  # Storing email
            session['user_name'] = user[1]  # Storing user name
            flash('Login successful!', 'success')
            return redirect('/dashboard_user')

        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

# User Dashboard
@app.route('/dashboard_user')
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
@app.route('/admin_add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin' not in session:
        return redirect('/login')

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])  # Secure password hashing

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, phone, dob, password) VALUES (%s, %s, %s, %s, %s)",
                       (name, email, phone, dob, password))
        mysql.connection.commit()
        cursor.close()

        flash('User added successfully!', 'success')
        return redirect('/admin_dashboard')

    return render_template('admin_add_user.html')

# Edit User (Admin)
@app.route('/admin_edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if 'admin' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        dob = request.form['dob']

        cursor.execute("UPDATE users SET name = %s, phone = %s, dob = %s WHERE id = %s",
                       (name, phone, dob, user_id))
        mysql.connection.commit()
        flash('User details updated successfully!', 'success')
        return redirect('/admin_dashboard')

    cursor.close()
    return render_template('admin_edit_user.html', user=user)

# Remove User (Admin)
@app.route('/admin_remove_user/<int:user_id>')
def admin_remove_user(user_id):
    if 'admin' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash('User removed successfully!', 'danger')
    return redirect('/admin_dashboard')

# Update User Profile
@app.route('/update', methods=['GET', 'POST'])
def update():
    if 'user_id' not in session:
        flash('Please log in to update your profile.', 'warning')
        return redirect('/login')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        dob = request.form['dob']
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if old_password and new_password and confirm_password:
            if not check_password_hash(user[5], old_password):
                flash('Old password is incorrect.', 'danger')
                return redirect('/update')
            if old_password == new_password:
                flash('Your new password is the same as the old password.', 'danger')
                return redirect('/update')
            if new_password != confirm_password:
                flash('New password and confirmation do not match.', 'danger')
                return redirect('/update')
            new_password_hashed = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password_hashed, session['user_id']))

        cursor.execute("UPDATE users SET name = %s, email = %s, phone = %s, dob = %s WHERE id = %s",
                       (name, email, phone, dob, session['user_id']))
        mysql.connection.commit()
        cursor.close()
        
        flash('Profile updated successfully!', 'success')
        return redirect('/dashboard_user')

    return render_template('update.html', user=user)
# Logout
@app.route('/logout')
def logout():
    session.clear() 
    flash('Logged out successfully.', 'info')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
