import datetime
from flask import Flask, render_template, url_for, request, redirect, flash, session, send_file
from flask_login import login_required
import pandas as pd
import sqlite3
import io
import os
import csv
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# Generate a random secret key if you don't have one
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('ITAM.db')
    conn.row_factory = sqlite3.Row
    return conn

''' ##### THIS USES SQLALCHEMY FOR THE CONNECTION OF THE BACKEND AND DATABASE

from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuring SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ITAM.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
'''

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
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('index.html', assets=assets)

@app.route("/export-excel")
@login_required
def export_excel():
    conn = get_db_connection()
    # Fetching data with the desired order
    assets = conn.execute('SELECT * FROM assets ORDER BY id DESC').fetchall()
    conn.close()

    # Define column names for the DataFrame
    column_names = ['ID', 'Site', 'Asset Type', 'Brand', 'Asset Tag', 'Serial Number', 
                    'Location', 'Campaign', 'Station Number', 'Purchase Date', 
                    'Sales Invoice Number', 'Model', 'Specifications', 'RAM Slot', 
                    'RAM Type', 'RAM Capacity', 'PC Name', 'Windows Version', 
                    'Last Update/Date Installed', 'Completed By']

    # Create a DataFrame from the assets with the specified column names
    df = pd.DataFrame(assets, columns=column_names)

    # Create a BytesIO object and save the DataFrame as an Excel file
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Assets')
    output.seek(0)

    # Get the current date in the format YYYY-MM-DD
    current_date = datetime.now().strftime("%Y-%m-%d")
    filename = f"ITAssetsInventory_{current_date}.xlsx"  # Desired filename format

    # Send the file to the user
    return send_file(output, as_attachment=True, attachment_filename=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/assets/', methods=["POST", "GET"])
@login_required
def assets():
    return render_template('assets.html')

@app.route("/import-csv", methods=["POST"])
@login_required
def import_csv():
    if 'csv_file' not in request.files:
        flash('No file part')
        return redirect(url_for('inventory'))
    
    file = request.files['csv_file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('inventory'))
    
    if file and file.filename.endswith('.csv'):
        # Read the CSV file
        csv_file = csv.reader(file.stream.read().decode('utf-8').splitlines())
        next(csv_file)  # Skip header row

        conn = get_db_connection()
        
        # Insert each row into the database
        for row in csv_file:
            conn.execute('INSERT INTO assets (site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, si_num, model, specs, ram_slot, ram_type, ram_capacity, pc_name, win_ver, last_upd, completed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], row[13], row[14], row[15], row[16], row[17], row[18]))
        
        conn.commit()
        conn.close()
        flash('CSV file imported successfully!')
    else:
        flash('Invalid file format. Please upload a CSV file.')

    return redirect(url_for('inventory'))

@app.route('/inventory/', methods=["POST", "GET"])
@login_required
def inventory():
    try:
        conn = get_db_connection()
        assets = conn.execute('SELECT * FROM assets').fetchall()
        conn.close()
    except Exception as e:
        flash(f'An error occurred: {e}')
        return redirect(url_for('index'))  # Redirect to the index or handle it as needed
    
    return render_template('inventory.html', assets=assets)

@app.route('/audit/', methods=["POST", "GET"])
@login_required
def audit():
    try:
        conn = get_db_connection()
        assets = conn.execute('SELECT * FROM assets ORDER BY id DESC').fetchall()
        users = conn.execute('SELECT * FROM user_accounts ORDER BY email ASC').fetchall()
        edit_assets = conn.execute('SELECT * FROM edit_assets WHERE status = "pending" ORDER BY updated_at DESC').fetchall()
        conn.close()
    except Exception as e:
        print("An error occurred:", e)
        return "An error occurred while fetching data.", 500  # Return a 500 error

    return render_template('audit.html', assets=assets, users=users, edit_assets=edit_assets)



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

@app.route('/add-asset/', methods=["GET", "POST"])
@login_required
def add_asset():
    if request.method == "POST":
        # Log the incoming data for debugging
        print(request.form)  # Print submitted data for debugging
        print("FORM SUBMITTED!!!") 
        
        # Get data from the form
        site = request.form.get('site')  
        asset_type = request.form.get('asset_type')
        brand = request.form.get('brand')
        asset_tag = request.form.get('asset_tag')
        serial_no = request.form.get('serial_no')
        location = request.form.get('location')
        campaign = request.form.get('campaign')
        station_no = request.form.get('station_no')
        pur_date = request.form.get('pur_date')
        si_num = request.form.get('si_num')
        model = request.form.get('model') 
        specs = request.form.get('specs')
        ram_slot = request.form.get('ram_slot')
        ram_type = request.form.get('ram_type')
        ram_capacity = request.form.get('ram_capacity')
        pc_name = request.form.get('pc_name')
        win_ver = request.form.get('win_ver')
        last_upd = request.form.get('last_upd')
        completed_by = request.form.get('completed_by')

        # Insert the data into the database
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO assets (site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, si_num, model, specs, ram_slot, ram_type, ram_capacity, pc_name, win_ver, last_upd, completed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         (site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, si_num, model, specs, ram_slot, ram_type, ram_capacity, pc_name, win_ver, last_upd, completed_by))
            conn.commit()
            flash('New IT asset added successfully!')
            print("Asset added successfully!")
        except Exception as e:
            print(f"Error: {e}")  # Log any error that occurs
            flash('An error occurred while adding the asset.')
        finally:
            conn.close()
        
        return redirect(url_for('inventory'))
    
    return render_template('add_asset.html')


@app.route('/delete-asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def delete_asset(asset_id):
    conn = get_db_connection()
    asset = conn.execute('SELECT * FROM assets WHERE id = ?', (asset_id,)).fetchone()
    
    if request.method == 'POST':
        password = request.form.get('password')
        user_email = session.get('user_email')

        # Fetch the current user to validate password
        user = conn.execute('SELECT * FROM user_accounts WHERE email = ?', (user_email,)).fetchone()

        if user and password == user['password']:  # Assuming plain-text passwords
            conn.execute('DELETE FROM assets WHERE id = ?', (asset_id,))
            conn.commit()
            flash('Asset deleted successfully.', 'success')
            conn.close()
            return redirect(url_for('inventory'))
        else:
            flash('Invalid password. Please try again.', 'danger')
    
    conn.close()
    return render_template('delete_asset.html', asset=asset)


@app.route('/edit-asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    conn = get_db_connection()
    asset = conn.execute('SELECT * FROM assets WHERE id = ?', (asset_id,)).fetchone()

    if not asset:
        flash('Asset not found.')
        return redirect(url_for('inventory'))

    if request.method == 'POST':
        # Get data from the form
        site = request.form.get('site')
        asset_type = request.form.get('asset_type')
        brand = request.form.get('brand')
        asset_tag = request.form.get('asset_tag')
        serial_no = request.form.get('serial_no')
        location = request.form.get('location')
        campaign = request.form.get('campaign')
        station_no = request.form.get('station_no')
        pur_date = request.form.get('pur_date')
        si_num = request.form.get('si_num')
        model = request.form.get('model')
        specs = request.form.get('specs')
        ram_slot = request.form.get('ram_slot')
        ram_type = request.form.get('ram_type')
        ram_capacity = request.form.get('ram_capacity')
        pc_name = request.form.get('pc_name')
        win_ver = request.form.get('win_ver')
        last_upd = request.form.get('last_upd')
        completed_by = request.form.get('completed_by')

        # Update the data in the database
        try:
            conn.execute('''UPDATE assets SET site = ?, asset_type = ?, brand = ?, asset_tag = ?, serial_no = ?, location = ?, campaign = ?, station_no = ?, pur_date = ?, si_num = ?, model = ?, specs = ?, ram_slot = ?, ram_type = ?, ram_capacity = ?, pc_name = ?, win_ver = ?, last_upd = ?, completed_by = ? WHERE id = ?''',
                         (site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, si_num, model, specs, ram_slot, ram_type, ram_capacity, pc_name, win_ver, last_upd, completed_by, asset_id))
            conn.commit()
            flash('Asset updated successfully!')
        except Exception as e:
            print(f"Error: {e}")
            flash('An error occurred while updating the asset.')
        finally:
            conn.close()

        return redirect(url_for('inventory'))
    
    conn.close()
    return render_template('edit_asset.html', asset=asset)

@app.route('/request-inventory/', methods=["POST", "GET"])
@login_required
def request_inventory():
    try:
        conn = get_db_connection()
        assets = conn.execute('SELECT * FROM assets').fetchall()
        conn.close()
    except Exception as e:
        flash(f'An error occurred: {e}')
        return redirect(url_for('index'))  # Redirect to the index or handle it as needed
    
    return render_template('request_inventory.html', assets=assets)


@app.route('/assets/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_asset_request(id):
    conn = get_db_connection()
    asset = conn.execute('SELECT * FROM assets WHERE id = ?', (id,)).fetchone()
    conn.close()

    if request.method == 'POST':
        data = {
            'site': request.form.get('site'),
            'asset_type': request.form.get('asset_type'),
            'brand': request.form.get('brand'),
            'asset_tag': request.form.get('asset_tag'),
            'serial_no': request.form.get('serial_no'),
            'location': request.form.get('location'),
            'campaign': request.form.get('campaign'),
            'station_no': request.form.get('station_no'),
            'pur_date': request.form.get('pur_date'),
            'si_num': request.form.get('si_num'),
            'model': request.form.get('model'),
            'specs': request.form.get('specs'),
            'ram_slot': request.form.get('ram_slot'),
            'ram_type': request.form.get('ram_type'),
            'ram_capacity': request.form.get('ram_capacity'),
            'pc_name': request.form.get('pc_name'),
            'win_ver': request.form.get('win_ver'),
            'last_upd': request.form.get('last_upd'),
            'requested_by': request.form.get('requested_by')
        }
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO edit_assets (id, site, asset_type, brand, asset_tag, serial_no, location, campaign, station_no, pur_date, si_num, model, specs, ram_slot, ram_type, ram_capacity, pc_name, win_ver, last_upd, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         ('edit', id, *data.values()))
            conn.commit()
            flash('Edit request submitted successfully!')
        except Exception as e:
            flash('An error occurred while requesting to edit the asset.')
        finally:
            conn.close()
         
        return redirect(url_for('audit'))
    
    conn.close()
    return render_template('request_edit.html', asset=asset)

@app.route('/audit/approve/<int:id>', methods=['POST'])
@login_required
def approve_edit(id):
    conn = get_db_connection()
    edit_request = conn.execute('SELECT * FROM edit_assets WHERE id = ?', (id,)).fetchone()
    
    if edit_request:
        conn.execute('''UPDATE assets SET site = ?, asset_type = ?, brand = ?, asset_tag = ?, serial_no = ?, location = ?, campaign = ?, station_no = ?, pur_date = ?, si_num = ?, model = ?, specs = ?, ram_slot = ?, ram_type = ?, ram_capacity = ?, pc_name = ?, win_ver = ?, last_upd = ?, completed_by = ? WHERE id = ?''',
                            (edit_request['site'], edit_request['asset_type'], edit_request['brand'], edit_request['asset_tag'], edit_request['serial_no'], edit_request['location'], edit_request['campaign'], edit_request['station_no'], edit_request['pur_date'], edit_request['si_num'], edit_request['model'], edit_request['specs'], edit_request['ram_slot'], edit_request['ram_type'], edit_request['ram_capacity'], edit_request['pc_name'], edit_request['win_ver'], edit_request['last_upd'], edit_request['completed_by'], edit_request['asset_id']))
        conn.execute('UPDATE edit_assets SET status = "approved" WHERE id = ?', (id,))
        conn.commit()
    
    conn.close()
    flash('Edit request approved and applied.', 'success')
    return redirect(url_for('audit'))

@app.route('/reject_edit/<int:edit_id>', methods=['POST'])
@login_required
def reject_edit(edit_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM edit_assets WHERE id = ?', (edit_id,))
    conn.commit()
    conn.close()
    flash('The edit request has been rejected.', 'success')
    return redirect(url_for('audit'))



if __name__ == "__main__":
    app.run(debug=True)
