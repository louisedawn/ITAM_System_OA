from flask import Flask, render_template, url_for, request, redirect, flash, session
import sqlite3
import os
from functools import wraps

app = Flask(__name__)

# Generate a random secret key if you don't have one
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('ITAM.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('home'))  # Redirect to the login page
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET"])
def home():
    if 'user_email' in session:
        return redirect(url_for('index'))  # Redirect to the index if already logged in
    return render_template('login.html')

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user_accounts WHERE email = ? AND password = ?',
                        (email, password)).fetchone()
    conn.close()
    
    if user:
        session['user_email'] = email  # Store the logged-in user email in session
        session['user_name'] = user['name']
        session['user_role'] = user['user_role']
        return redirect(url_for('index'))
    else:
        flash('Invalid email or password! Please try again!')
        return redirect(url_for('home'))

@app.route("/index")
@login_required
def index():
    return render_template('index.html')

@app.route('/assets/', methods=["POST", "GET"])
@login_required
def assets():
    return render_template('assets.html')

@app.route("/add-asset/", methods=["POST"])
@login_required
def add_asset():
    site = request.form.get('site')  # Fixed to match HTML
    asset_type = request.form.get('asset_type')
    brand = request.form.get('brand')
    asset_tag = request.form.get('asset_tag')
    serial_no = request.form.get('serial_no')  # Fixed to match HTML
    location = request.form.get('location')  # Fixed to match HTML
    campaign = request.form.get('campaign')
    station_no = request.form.get('station_no')
    pur_date = request.form.get('pur_date')  # Fixed to match HTML
    model = request.form.get('model')
    specs = request.form.get('specs')
    ram_slot = request.form.get('ram_slot')
    pc_name = request.form.get('pc_name')
    win_ver = request.form.get('win_ver')
    last_upd = request.form.get('last_upd')
    completed_by = request.form.get('completed_by')
    
    conn = get_db_connection()
    conn.execute('INSERT INTO assets (site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, model, specs, ram_slot, pc_name, win_ver, last_upd, completed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (site, asset_type, brand, asset_tag, serial_no, location,
                  campaign, station_no, pur_date, model, specs, ram_slot, pc_name, win_ver, last_upd, completed_by))
    conn.commit()
    conn.close()
    return redirect(url_for('inventory'))

@app.route('/inventory/', methods=["POST", "GET"])
@login_required
def inventory():
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets').fetchall()
    conn.close()
    return render_template('inventory.html', assets=assets)

@app.route('/audit/', methods=["POST", "GET"])
@login_required
def audit():
    return render_template('audit.html')

#for workstation
@app.route('/workstation/', methods=["POST", "GET"])
@login_required
def workstation():
    return render_template('workstation.html')

#for PO
@app.route('/reques_form/', methods=["POST", "GET"])
def request_form():
    return render_template('request_form.html')

@app.route('/request/', methods=["POST", "GET"])
@login_required
def request_inventory():
    return render_template('request.html')

@app.route('/systemusers/', methods=["GET"])
@login_required
def system_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM user_accounts').fetchall()
    conn.close()
    return render_template('systemusers.html', users=users)

@app.route('/add-user', methods=["POST"])
@login_required
def add_user():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    role = request.form.get('role')
    
    conn = get_db_connection()
    conn.execute('INSERT INTO user_accounts (email, name, password, user_role) VALUES (?, ?, ?, ?)',
                 (email, name, password, role))
    conn.commit()
    conn.close()
    
    flash('New user account added successfully!')
    return redirect(url_for('system_users'))

@app.route('/edit_user/<email>', methods=["GET", "POST"])
@login_required
def edit_user(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user_accounts WHERE email = ?', (email,)).fetchone()

    if request.method == "POST":
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        super_admin_password = request.form.get('super_admin_password')

        # Fetch the currently logged-in super-admin user
        super_admin = conn.execute('SELECT * FROM user_accounts WHERE email = ? AND user_role = "Super-Admin"',
                                   (session['user_email'],)).fetchone()

        if not super_admin:
            flash('You must be a super-admin to edit user details.')
            return redirect(url_for('home'))

        # Check if current password is correct
        if current_password != user['password']:
            flash('Current password is incorrect.')
            return render_template('edit_user.html', user=user)

        # Check if super-admin password is correct
        if super_admin_password != super_admin['password']:
            flash('Super-Admin password is incorrect.')
            return render_template('edit_user.html', user=user)

        # Check if new password and confirm password match
        if new_password and new_password != confirm_password:
            flash('New password and confirmation do not match.')
            return render_template('edit_user.html', user=user)

        # Prepare the update data
        update_data = {
            'name': request.form.get('name'),
            'user_role': request.form.get('role'),
            'email': email
        }

        if new_password:
            update_data['password'] = new_password

        # Update user details in the database
        query = 'UPDATE user_accounts SET name = :name, user_role = :user_role {password_clause} WHERE email = :email'.format(
            password_clause=', password = :password' if new_password else ''
        )
        conn.execute(query, update_data)
        conn.commit()
        conn.close()

        flash('User account updated successfully!')
        return redirect(url_for('system_users'))

    conn.close()
    return render_template('edit_user.html', user=user)



@app.route('/delete-user/<email>', methods=["GET", "POST"])
@login_required
def delete_user(email):
    conn = get_db_connection()
    conn.execute('DELETE FROM user_accounts WHERE email = ?', (email,))
    conn.commit()
    conn.close()
    flash('User account deleted successfully!')
    return redirect(url_for('system_users'))

@app.route("/logout")
def logout():
    session.pop('user_email', None)  # Remove user_email from the session
    flash('You have successfully logged out!')
    return redirect(url_for('home'))

@app.after_request
def add_header(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    return response

@app.route('/confirm-delete/<email>', methods=["GET", "POST"])
@login_required
def confirm_delete(email):
    if request.method == "POST":
        # Check the password provided by the logged-in user
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user_accounts WHERE email = ?', (session['user_email'],)).fetchone()

        if user and password == user['password']:
            # Password is correct; proceed to delete the user
            conn.execute('DELETE FROM user_accounts WHERE email = ?', (email,))
            conn.commit()
            flash('User account deleted successfully!')
            return redirect(url_for('system_users'))
        else:
            flash('Incorrect password. Please try again.')
            return redirect(url_for('confirm_delete', email=email))

    return render_template('confirm_delete.html', email=email)




if __name__ == "__main__":
    app.run(debug=True)
