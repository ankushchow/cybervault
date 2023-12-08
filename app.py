from flask import Flask, request, redirect, session, render_template, flash,jsonify,url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import datetime as dt
import subprocess
import openai
import requests
from flask_talisman import Talisman
import psutil
import time
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)
stime=5
app.permanent_session_lifetime = dt.timedelta(minutes=stime)
openai.api_key = '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'
Talisman(app, content_security_policy=None)

NEXTDNS_BASE_URL = "https://api.nextdns.io/profiles/"
NEXTDNS_PROFILE_ID = '253d7c'
NEXTDNS_API_KEY = 'bb0a0e875049a38df2c74accb08fcd19d332be42'


# Initialize IDS status, mode, and process
ids_status = False
ids_mode = "normal"  # Possible values: "aggressive", "normal"
ids_process = None

idsAtype = ""
idsAction = ""

def get_firewall_stat():
    try:
        result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, check=True)
        if 'inactive' in result.stdout.lower():
            return False
        else:
            return True
    except subprocess.CalledProcessError:
        # Handle errors (e.g., if UFW is not installed)
        return False

@app.route('/get_firewall_status')
def get_firewall_status():
    try:
        result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, check=True)
        is_active = 'inactive' not in result.stdout.lower()
        return jsonify({'firewall_active': is_active})
    except subprocess.CalledProcessError:
        # Handle errors (e.g., if UFW is not installed)
        return jsonify({'firewall_active': False})


firewall_process = get_firewall_stat()

db_config = {
    'host': 'localhost',
    'user': 'cybervault_user',
    'password': 'your_password',
    'database': 'cybervault_db'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def insert_log(log_type, log_status, log_description):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert log entry
        sql = "INSERT INTO Logs (logType, logTime, logStatus, logDescription) VALUES (%s, %s, %s, %s)"
        log_time = dt.datetime.now()
        data_to_insert = (log_type, log_time, log_status, log_description)

        cursor.execute(sql, data_to_insert)
        conn.commit()

    except Exception as e:
        print(f"Error inserting into the log table: {e}")

    finally:
        cursor.close()
        conn.close()

@app.route('/')
def index():

    global firewall_process
    
    if 'loggedin' in session:
        try:
            # Establish database connection
            conn = get_db_connection()

            # Fetch count from the 'ids' table
            cursor_ids = conn.cursor(dictionary=True)
            cursor_ids.execute('SELECT COUNT(*) as count FROM IDS')
            result_ids = cursor_ids.fetchone()
            count_ids = result_ids['count']
            cursor_ids.close()

            # Fetch count from the 'Logs' table
            cursor_logs = conn.cursor(dictionary=True)
            cursor_logs.execute('SELECT COUNT(*) as count FROM Logs')
            result_logs = cursor_logs.fetchone()
            count_logs = result_logs['count']
            cursor_logs.close()
            
            cursor_dns = conn.cursor(dictionary=True)
            cursor_dns.execute("SELECT COUNT(*) as count FROM dns_records WHERE status = 'Active'")
            dns_active = cursor_dns.fetchone()['count'] > 0
            cursor_dns.close()

            # Query for VPN status
            cursor_vpn = conn.cursor(dictionary=True)
            cursor_vpn.execute("SELECT COUNT(*) as count FROM vpns WHERE status = 'Active'")
            vpn_active = cursor_vpn.fetchone()['count'] > 0
            cursor_vpn.close()

            
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ssid FROM wifi LIMIT 1")  # Assuming the table is named 'wifi' and has a column 'ssid'
            wifi_record = cursor.fetchone()
            wifi_name = wifi_record['ssid'] if wifi_record else 'Not Set'
            cursor.close()

        except mysql.connector.Error as e:
            print(f"Database error: {e}")
            count_ids = 0
            count_logs = 0
            firewall_active = False
            dns_active = False
            vpn_active = False
        finally:
            # Close the database connection
            if conn.is_connected():
                conn.close()
                
        most_blocked_domain, blocked_ratio, blocked_count = get_nextdns_analytics()

        return render_template('index.html', count_ids=count_ids, count_logs=count_logs, wifi_name=wifi_name, most_blocked_domain=most_blocked_domain, blocked_ratio=blocked_ratio, blocked_count=blocked_count, firewall_active=firewall_process, dns_status=dns_active, vpn_status=vpn_active)
    
    return redirect('/login')

#Login function that checks hashed password and adds to session
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = 'rememberMe' in request.form
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.close()
        conn.close()

        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['username'] = account['username']
            session.permanent = True
            insert_log("Login", "Success", f"User logged in successfully")

            # Redirect to home page
            response = redirect('/')

            # Set a cookie for the username if Remember Me is checked
            if remember_me:
                response.set_cookie('remember_username', username, max_age=60*60*24*30)  # Expires in 30 days

            return response

        else:
            flash('Incorrect username/password!')
            insert_log("Login", "Failure", f"Failed login attempt for username: {username}")

    # Check if the 'remember_username' cookie exists
    remembered_username = request.cookies.get('remember_username', '')
    return render_template('login.html', remembered_username=remembered_username)

#Maximum on one user for signup as the device supports only one user from the ethernet port
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if a user already exists
        cursor.execute('SELECT COUNT(*) AS user_count FROM users')
        result = cursor.fetchone()
        if result['user_count'] >= 1:
            cursor.close()
            conn.close()
            insert_log("Signup", "Failure", "Signup attempt when a user already exists")
            flash('Only one user account is allowed!')
            return redirect('/login')

        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        place_of_birth = request.form['place_of_birth']

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect('/signup')

        hashed_password = generate_password_hash(password)

        try:
            cursor.execute(
                'INSERT INTO users (username, password, place_of_birth) VALUES (%s, %s, %s)', 
                (username, hashed_password, place_of_birth)
            )
            conn.commit()
            insert_log("Signup", "Success", f"New user {username} signed up successfully")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
            insert_log("Signup", "Failure", f"Database error during signup: {err}")
        finally:
            cursor.close()
            conn.close()
        
        return redirect('/login')

    return render_template('signup.html')
    
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')  # assuming username is needed to identify user
        security_answer = request.form.get('security_answer')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("New passwords do not match!")
            return redirect('/forgotpassword')

        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if the security answer matches
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and user['place_of_birth'].lower() == security_answer.lower():
            # Update the password
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
            conn.commit()
            flash("Password successfully updated.")
            insert_log("Password", "Success", f"Password reset for user: {username}")
            return redirect('/login')
        else:
            flash("Invalid username or security answer.")
            insert_log("Password", "Failure", f"Invalid reset attempt for username: {username}")

        cursor.close()
        conn.close()

    return render_template('forgotpassword.html')

@app.route('/resetpassword', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], old_password):
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
            conn.commit()
            insert_log("Password", "Success", f"Password changed for user: {username}")
            flash("Password has been updated.")
            return redirect('/login')
        else:
            flash("Invalid username or password.")
            insert_log("Password", "Failure", f"Failed password change attempt for username: {username}")

        cursor.close()
        conn.close()

    return redirect('/login')



@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    insert_log("Logout", "Success", f"User logged out")
    return redirect('/login')
    
    

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = dt.timedelta(minutes=5)
    
@app.route('/dns-over-httpsdis')
def dns_over_https():
    if 'loggedin' not in session:
        return redirect('/login')    
        
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT id, name, status FROM dns_records")  # Adjust your query as needed
        dns_records = cursor.fetchall()
    except mysql.connector.Error as e:
        # Error handling
        dns_records = []
    finally:
        cursor.close()
        connection.close()

    return render_template('dns-over-httpsdis.html', dns_record=dns_records)
    
#Adds to dns table after regex verification    
@app.route('/dns-add', methods=['GET', 'POST'])
def dns_add():
    if 'loggedin' not in session:
        return redirect('/login')
        
    if request.method == 'POST':
        name = request.form.get('name')
        dns = request.form.get('dns')
        backup_dns = request.form.get('backup_dns')

        # Regular expression for validating an IP address
        def validate_ip_address(address):
            pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
            return re.match(pattern, address)

        # Validate DNS and Backup DNS
        if not validate_ip_address(dns) or not validate_ip_address(backup_dns):
            flash("Invalid DNS IP format", "error")
            return redirect('/dns-add')

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            sql_insert_query = """
                INSERT INTO dns_records (name, dns, backup_dns)
                VALUES (%s, %s, %s)
            """
            record_tuple = (name, dns, backup_dns)
            cursor.execute(sql_insert_query, record_tuple)
            connection.commit()
            flash("DNS record added successfully", "success")
        except mysql.connector.Error as e:
            flash(f"Failed to add DNS record: {str(e)}", "error")
            return redirect('/dns-add')
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

        return redirect('/dns-over-httpsdis')

    return render_template('dns-add.html')

#Updates dns status if VaultGuard is not activated as it also secures DNS.
@app.route('/update_status', methods=['POST'])
def update_status():
    
    if 'loggedin' not in session:
        return redirect('/login')
        
    try:
        nextdns_status = subprocess.check_output(['nextdns', 'status'], stderr=subprocess.STDOUT).decode('utf-8').strip()
        if 'running' in nextdns_status:
            return jsonify({'success': False, 'error': 'VaultGuard is on. Cannot update DNS while it is running.'})
    except subprocess.CalledProcessError:
        return jsonify({'success': False, 'error': 'Random error, refresh and try again.'})

    dns_id = request.json.get('dns_id')
    new_status = request.json.get('new_status')

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # If new status is 'active', set all other DNS records to 'inactive'
        if new_status == 'Active':
            cursor.execute("UPDATE dns_records SET status = 'Not Active'")

        update_query = "UPDATE dns_records SET status = %s WHERE id = %s"
        cursor.execute(update_query, (new_status, dns_id))
        connection.commit()

        # Update system DNS settings if necessary
        if new_status == 'Active':
            # Fetch the primary DNS and backup DNS details
            cursor.execute("SELECT dns, backup_dns FROM dns_records WHERE id = %s", (dns_id,))
            record = cursor.fetchone()
            primary_dns, backup_dns = record

            # Get the default network connection name
            result = subprocess.run(["sudo","nmcli", "-t", "-f", "NAME", "con", "show", "--active"], capture_output=True, text=True, check=True)
            default_con = result.stdout.strip().split("\n")[0]

            # Update DNS settings using nmcli
            dns_string = f"{primary_dns},{backup_dns}" if backup_dns else primary_dns
            subprocess.run(["sudo","nmcli", "con", "mod", default_con, "ipv4.dns", dns_string], check=False)
            subprocess.run(["sudo","nmcli", "con", "up", default_con], check=False)
            #subprocess.run(["sudo","systemd-resolve", "--flush-caches"], check=True)
            insert_log("DNS", "Success", f"DNS {dns_id} status updated to {new_status}")

    except mysql.connector.Error as error:
        insert_log("DNS Status Update", "Failure", f"Failed to update DNS status: {str(error)}")
        flash(f"Failed to update DNS status: {str(error)}")
        return jsonify({'success': False, 'error': str(error)})
    except subprocess.CalledProcessError as sp_error:
        insert_log("DNS Status Update", "Failure", f"Failed to update DNS status: {str(sp_error)}")
        flash(f"Failed to update DNS status: {str(sp_error)}")
        return jsonify({'success': False, 'error': str(sp_error)})
    finally:
        cursor.close()
        connection.close()

    return jsonify({'success': True})

    
@app.route('/dns-edit/<int:dns_id>', methods=['GET', 'POST'])
def dns_edit(dns_id):
    if 'loggedin' not in session:
        return redirect('/login')

    connection = get_db_connection()
    cursor = connection.cursor(buffered=True)

    if request.method == 'POST':
        # Get data from form
        name = request.form['name']
        dns = request.form['dns']
        backup_dns = request.form['backup_dns']

        try:
            # Update record in the database
            update_query = "UPDATE dns_records SET name = %s, dns = %s, backup_dns = %s WHERE id = %s"
            cursor.execute(update_query, (name, dns, backup_dns, dns_id))
            connection.commit()
            flash("DNS record updated successfully", "success")
        except mysql.connector.Error as e:
            flash(f"Failed to update DNS record: {str(e)}", "error")
        finally:
            cursor.close()
            connection.close()

        return redirect('/dns-over-httpsdis')

    # For a GET request, fetch the existing data to prefill the form
    try:
        cursor.execute("SELECT id, name, dns, backup_dns FROM dns_records WHERE id = %s", (dns_id,))
        record = cursor.fetchone()
    except mysql.connector.Error as e:
        record = None
        flash(f"Failed to fetch DNS record: {str(e)}", "error")
        return redirect('/dns-over-httpsdis')
    finally:
        cursor.close()
        connection.close()

    return render_template('dn-sedit.html', record=record)

@app.route('/delete_dns/<int:dns_id>', methods=['POST'])
def delete_dns(dns_id):
    if 'loggedin' not in session:
        return redirect('/login')

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Delete the DNS record from the database
        cursor.execute("DELETE FROM dns_records WHERE id = %s", (dns_id,))
        connection.commit()

        flash('DNS record deleted successfully.')
    except mysql.connector.Error as db_error:
        flash(f'Database error: {str(db_error)}')
        return jsonify({'success': False, 'error': str(db_error)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return jsonify({'success': True})


@app.route('/chatbot-system')
def chatbot_system():
    if 'loggedin' not in session:
        return redirect('/login')
           
    return render_template('chatbotsystem.html')
    
@app.route('/chatbot-discovery')
def chatbot_disovery():
    if 'loggedin' not in session:
        return redirect('/login')
            
    return render_template('chatbotdiscovery.html')
    
#Discovery chatbot uses OPENAI framework to work with a context to restrict and help the user queries be targeted and easier understood by the AI    
@app.route('/send_message_discovery', methods=['POST'])
def send_message_discovery():
    try:
        user_message = request.json['message']

        # Define the context or introduction for the conversation
        intro_context = (
            "You are an assistant specialized in cybersecurity, focusing on topics "
            "like home and network security. Provide helpful and accurate information "
            "on these subjects. If the user asks questions that are not related to this, inform them that you are only trained to assist in cybersecurity."
        )

        # Create the chat response with the defined context
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": intro_context},
                {"role": "user", "content": user_message},
            ]
        )

        return jsonify({"reply": response.choices[0].message['content']})

    except Exception as e:
        # Handle other generic errors
        return jsonify({"error": "Internal server error", "details": str(e)})
    
        
@app.route('/vpn')
def vpn():
    if 'loggedin' not in session:
        return redirect('/login')
            
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all VPN data from the database
    cursor.execute('SELECT * FROM vpns')
    vpns = cursor.fetchall()  # Assuming 'vpns' is your table name

    cursor.close()
    conn.close()

    # Pass the fetched VPNs to the template
    return render_template('vpn.html', vpns=vpns)

#Turns on the connection through Network Manager
@app.route('/update_vpn_status', methods=['POST'])
def update_vpn_status():
    if 'loggedin' not in session:
        return redirect('/login')
            
    data = request.get_json()
    vpn_id = data.get('vpn_id')
    new_status = data.get('new_status')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch the VPN name based on the provided vpn_id
        cursor.execute('SELECT name FROM vpns WHERE id = %s', (vpn_id,))
        vpn_data = cursor.fetchone()
        vpn_name = vpn_data[0]

        # Deactivate all other VPNs first if activating one
        if new_status == 'Active':
            cursor.execute('UPDATE vpns SET status = "Not Active" WHERE id != %s', (vpn_id,))
            conn.commit()

            # Deactivate all VPNs via NetworkManager except the one to be activated
            subprocess.run(['nmcli', 'con', 'down', vpn_name], check=False)

        # Activate or deactivate the selected VPN via NetworkManager
        nmcli_command = ['nmcli', 'con', 'up' if new_status == 'Active' else 'down', vpn_name]
        subprocess.run(nmcli_command, check=True)

        # Update the status of the selected VPN in the database
        cursor.execute('UPDATE vpns SET status = %s WHERE id = %s', (new_status, vpn_id))
        conn.commit()

        insert_log("VPN", "Success", f"VPN {vpn_name} status updated to {new_status}")
        flash("VPN status updated successfully")
        return jsonify({'success': True})

    except subprocess.CalledProcessError as nmcli_error:
        # Handle errors from nmcli
        flash("Failed to update VPN status with NetworkManager")
        return jsonify({'success': False, 'error': 'Failed to update VPN status with NetworkManager: ' + str(nmcli_error)})

    except Exception as e:
        insert_log("VPN", "Failure", f"Failed to update VPN status: {str(e)}")
        flash(f"Failed to update VPN status: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)})

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        
#Adds VPN through Network Manager and OVPN files which use OpenVPN for simple and quick configuration. 
@app.route('/vpn-add', methods=['GET', 'POST'])
def vpn_add():
    if 'loggedin' not in session:
        return redirect('/login')
            
    if request.method == 'POST':
        vpn_name = request.form.get('name')
        vpn_type = request.form.get('type')
        vpn_server_choice = request.form.get('server')
        vpn_username = request.form.get('username')
        vpn_password = request.form.get('password')

        server_mapping = {
            'australia': 'VPN/Australia.ovpn',
            'usa': 'VPN/USA.ovpn',
            'uk': 'VPN/UK.ovpn',
        }
        ovpn_file = server_mapping.get(vpn_server_choice.lower())
        default_vpn_name = os.path.splitext(os.path.basename(ovpn_file))[0]  # Extracts name without the .ovpn

        if ovpn_file and os.path.exists(ovpn_file):
            # Import VPN using nmcli
            cmd_import = ['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', ovpn_file]
            process_import = subprocess.run(cmd_import, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if process_import.returncode != 0:
                flash(f"Failed to add VPN: {process_import.stderr}")
                return redirect('/vpn-add')

            # Rename the imported VPN connection to the user's desired name if it is different
            if default_vpn_name != vpn_name:
                cmd_rename = ['nmcli', 'connection', 'modify', default_vpn_name, 'connection.id', vpn_name]
                subprocess.run(cmd_rename, check=False)  # We don't check this command because nmcli doesn't provide useful output here

            # Set VPN username and password
            cmd_modify_user = ['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', f'username={vpn_username}']
            cmd_modify_pw_flags = ['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', 'password-flags=0']
            cmd_modify_pw = ['nmcli', 'connection', 'modify', vpn_name, '+vpn.secrets', f'password={vpn_password}']
            
            subprocess.run(cmd_modify_user, check=False)
            subprocess.run(cmd_modify_pw_flags, check=False)
            subprocess.run(cmd_modify_pw, check=False)

            # Add the new VPN record to the database
            connection = get_db_connection()
            cursor = connection.cursor()
            try:
                cursor.execute(
                    'INSERT INTO vpns (name, type, server, username, password) VALUES (%s, %s, %s, %s, %s)',
                    (vpn_name, vpn_type, vpn_server_choice, vpn_username, vpn_password)
                )
                connection.commit()
            except mysql.connector.Error as error:
                insert_log("VPN", "Failure", f"Failed to add VPN: {str(error)}")
                flash(f"Database error: {error}")
                return redirect('/vpn-add')
            finally:
                cursor.close()
                connection.close()

            insert_log("VPN", "Success", f"New VPN {vpn_name} added successfully")
            flash('VPN added successfully!')
            return redirect('/vpn')
        else:
            flash('Server .ovpn file does not exist.')
            return redirect('/vpn-add')

    else:
        return render_template('vpn-add.html')


@app.route('/vpn-edit/<int:vpn_id>', methods=['GET', 'POST'])
def vpn_edit(vpn_id):
    if 'loggedin' not in session:
        return redirect('/login')
            
    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == 'POST':
        # Extract data from form
        new_name = request.form.get('name')
        new_type = request.form.get('type')
        new_server = request.form.get('server')
        new_username = request.form.get('username')
        new_password = request.form.get('password')

        # Fetch the current VPN details from the database for comparison
        cursor.execute("SELECT name, type, server, username, password FROM vpns WHERE id = %s", (vpn_id,))
        vpn = cursor.fetchone()

        if vpn:
            try:
                if vpn[2] != new_server:
                    # Delete the existing VPN connection using nmcli
                    subprocess.run(['nmcli', 'connection', 'delete', vpn[0]], check=True)

                    # Use server_mapping to get the path to the new .ovpn file
                    server_mapping = {
                        'australia': 'VPN/Australia.ovpn',
                        'usa': 'VPN/USA.ovpn',
                        'uk': 'VPN/UK.ovpn',
                    }
                    ovpn_file = server_mapping.get(new_server.lower())
                    default_vpn_name = os.path.splitext(os.path.basename(ovpn_file))[0]
                    if ovpn_file and os.path.exists(ovpn_file):
                        # Import the new VPN using nmcli
                        subprocess.run(['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', ovpn_file], check=True)

                        # Rename the imported VPN connection to the new name
                        #if new_name and os.path.splitext(os.path.basename(ovpn_file))[0] != new_name:
                        subprocess.run(['nmcli', 'connection', 'modify', default_vpn_name, 'connection.id', new_name], check=True)

                    # Set VPN username and password if provided
                    if new_username:
                        subprocess.run(['nmcli', 'connection', 'modify', new_name, '+vpn.data', f'username={new_username}'], check=False)
                    if new_password:
                        subprocess.run(['nmcli', 'connection', 'modify', new_name, '+vpn.data', 'password-flags=0'], check=False)
                        subprocess.run(['nmcli', 'connection', 'modify', new_name, '+vpn.secrets', f'password={new_password}'], check=False)

                else:
                    # Handle updates that don't require VPN re-creation
                    if new_name and new_name != vpn[0]:
                        subprocess.run(['nmcli', 'connection', 'modify', vpn[0], 'connection.id', new_name], check=False)
                    if new_username and new_username != vpn[3]:
                        subprocess.run(['nmcli', 'connection', 'modify', vpn[0], '+vpn.data', f'username={new_username}'], check=False)
                    if new_password and new_password != vpn[4]:
                        subprocess.run(['nmcli', 'connection', 'modify', vpn[0], '+vpn.data', 'password-flags=0'], check=False)
                        subprocess.run(['nmcli', 'connection', 'modify', vpn[0], '+vpn.secrets', f'password={new_password}'], check=False)

                # Update the database record with new details
                cursor.execute(
                    "UPDATE vpns SET name = %s, type = %s, server = %s, username = %s, password = %s WHERE id = %s",
                    (new_name, new_type, new_server, new_username, new_password, vpn_id)
                )
                insert_log("VPN", "Success", f"VPN {vpn[0]} edited successfully")
                connection.commit()
                flash('VPN updated successfully!')

            except subprocess.CalledProcessError as e:
                connection.rollback()
                insert_log("VPN", "Failure", f"Failed to edit VPN: {str(e)}")
                flash(f"Failed to update VPN: {e}")
                return redirect(url_for('vpn_edit', vpn_id=vpn_id))

            finally:
                cursor.close()
                connection.close()

            return redirect('/vpn')

    else:
        # GET request: render the edit form with pre-filled data
        cursor.execute("SELECT * FROM vpns WHERE id = %s", (vpn_id,))
        vpn = cursor.fetchone()
        cursor.close()
        connection.close()

        if vpn:
            return render_template('vpn-edit.html', vpn=vpn)
        else:
            flash('VPN not found!')
            return redirect(url_for('vpn_edit', vpn_id=vpn_id))  

@app.route('/delete_vpn/<int:vpn_id>', methods=['POST'])
def delete_vpn(vpn_id):
    if 'loggedin' not in session:
        return redirect('/login')

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch the VPN name for nmcli command
        cursor.execute("SELECT name FROM vpns WHERE id = %s", (vpn_id,))
        vpn = cursor.fetchone()

        if vpn:
            vpn_name = vpn[0]

            # Delete the VPN using nmcli
            subprocess.run(['nmcli', 'connection', 'delete', vpn_name], check=True)

            # Delete the VPN record from the database
            cursor.execute("DELETE FROM vpns WHERE id = %s", (vpn_id,))
            connection.commit()

            flash('VPN deleted successfully.')
        else:
            flash('VPN not found.')

    except subprocess.CalledProcessError as e:
        flash(f'Failed to delete VPN: {e}')
        return jsonify({'success': False, 'error': str(e)})
    except mysql.connector.Error as db_error:
        flash(f'Database error: {str(db_error)}')
        return jsonify({'success': False, 'error': str(db_error)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return jsonify({'success': True})

#The system chatbot uses a detailed context that guides the OpenAI framework to understand how it should parse and return the user queries and this function will dynamically call the respective fuctions based on what OpenAI replied with.
@app.route('/send_message_system', methods=['POST'])
def send_message_system():
    user_message = request.json['message']
    conversation_history = session.get('conversation_history', [])

    # Add the new user message to the conversation history
    conversation_history.append({"role": "user", "content": user_message})

    # Define the context or introduction for the conversation
    intro_context = (
        "You are an AI assistant specialized in DNS, VPN, and Firewall management tasks, such as adding DNS records, "
        "editing DNS records, removing DNS records, turning firewall on and off and managing VPN configurations. When provided with the necessary "
        "details for a task, you will respond with a simple templated message indicating the action to take. For DNS management, "
        "to add a record, respond with 'Action: Add DNS - name: example, dns: 1.1.1.1, backup_dns: 2.2.2.2'. To edit a DNS record, "
        "respond with 'Action: Edit DNS - name: example, dns: 1.1.1.1, backup_dns: 2.2.2.2'. To delete a DNS record, "
        "respond with 'Action: Delete DNS - name: exampledns'. To turn on DNS, respond with 'Action: Turn On DNS - name: exampleDNS'. "
        "To turn off DNS, respond with 'Action: Turn Off DNS - name: exampleDNS'. For VPN management, to add a VPN, respond with "
        "'Action: Add VPN - name: exampleVPN, server: USA, username: user123, password: pass123'. To edit a VPN, "
        "respond with 'Action: Edit VPN - name: currentVPNName, new_name: newExampleVPN, server: UK, username: newuser123, password: newpass123'. "
        "Do not provide steps or ask for confirmations, just the action and the details. If the details are not provided in this format, "
        "you will ask the user to provide them accordingly unless its to edit a vpn, where only name is required and rest are optional. "
        "To delete a VPN, respond with 'Action: Delete VPN - name: exampleVPN'. To turn on a VPN, respond with "
        "'Action: Turn On VPN - name: exampleVPN'. To turn off a VPN, respond with 'Action: Turn Off VPN - name: exampleVPN'. For Firewall Management, "
        "To turn on the firewall, respond with 'Action: Turn On Firewall - name: firewall. To turn off the firewall, respond with 'Action: Turn Off Firewall - name: firewall'." 
    )

    # Construct the messages payload including the conversation history
    messages = [
        {"role": "system", "content": intro_context}
    ] + conversation_history

    # Create the chat response with the defined context
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=messages
    )

    # Extract the message content from the response
    bot_message = response.choices[0].message['content']
    
    # Add the bot's response to the conversation history
    conversation_history.append({"role": "assistant", "content": bot_message})
    
    # Update the session with the latest conversation history
    session['conversation_history'] = conversation_history

    # Check if the conversation indicates an action or if more information is needed
    if "Action:" in bot_message:
        try:
            action_part, params_part = bot_message.split(" - ", 1)
            
            # Clear the conversation history after performing an action
            session.pop('conversation_history', None)

            param_entries = params_part.split(", ")
            param_dict = {entry.split(": ")[0].strip(): entry.split(": ")[1].strip() for entry in param_entries if ": " in entry}

            if action_part.startswith('Action: Add DNS'):
                response = dns_add_internal(param_dict['name'], param_dict['dns'], param_dict['backup_dns'])
            elif action_part.startswith('Action: Edit DNS'):
                response = dns_edit_internal(param_dict['name'], param_dict['dns'], param_dict['backup_dns'])
            elif action_part.startswith('Action: Delete DNS'):
                response = dns_delete_internal(param_dict['name'])
            elif action_part.startswith('Action: Add VPN'):
                response = vpn_add_internal(param_dict['name'], param_dict['server'], param_dict['username'], param_dict['password'])
            elif action_part.startswith('Action: Delete VPN'):
                vpn_name = param_dict['name']
                response = vpn_delete_internal(vpn_name)
            elif action_part.startswith('Action: Edit VPN'):
                current_name = param_dict.pop('name', None)
                if current_name is None:
                    return jsonify({"reply": "The current VPN name is required for editing."})
                response = vpn_edit_internal(current_name, **param_dict)
            elif action_part.startswith('Action: Turn On VPN'):
                vpn_name = param_dict['name']
                response = vpn_toggle_by_name(vpn_name, 'Active')
            elif action_part.startswith('Action: Turn Off VPN'):
                vpn_name = param_dict['name']
                response = vpn_toggle_by_name(vpn_name, 'Not Active')
            elif action_part.startswith('Action: Turn On DNS'):
                dns_name = param_dict['name']
                response = update_dns_status(dns_name, 'Active')
            elif action_part.startswith('Action: Turn Off DNS'):
                dns_name = param_dict['name']
                response = update_dns_status(dns_name, 'Not Active')
            elif action_part.startswith('Action: Turn Off Firewall'):
                response = toggle_firewall_internal(False)
            elif action_part.startswith('Action: Turn On Firewall'):
                response = toggle_firewall_internal(True)
            
            return response
            
        except openai.error.OpenAIError as e:
            # Handle OpenAI specific errors
            return jsonify({"reply": "OpenAI service error", "details": str(e)})
        except IndexError:
            # Handle the case where the bot's message isn't in the expected format
            return jsonify({"reply": "There was an error processing the action. Please try again."})
        except KeyError as e:
            # Handle the case where expected parameters are missing
            return jsonify({"reply": f"Missing parameter: {e}. Please provide all required details."})
    else:
        # If the response is a question or not an action, return the bot's message to ask for more information
        return jsonify({"reply": bot_message})

#Internal functions that work with the System VaultBot
def toggle_firewall_status(turn_on):
    global ids_process, firewall_process
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})

    if ids_process is None:
        if turn_on:
            # Activate the firewall
            subprocess.run(['sudo', 'ufw', 'enable'], check=True)
            firewall_process = True
            insert_log("Firewall", "Active", "Firewall turned on")
        else:
            # Deactivate the firewall
            subprocess.run(['sudo', 'ufw', 'disable'], check=True)
            firewall_process = False
            insert_log("Firewall", "Not Active", "Firewall turned off")
    else:
        flash("Firewall cannot be toggled when IDS process is active.")
        return jsonify({"error": "Firewall cannot be toggled when IDS process is active."})

    return jsonify({"message": "Firewall status updated."})

def update_dns_status(dns_name, new_status):
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the requested DNS is already in the desired state
        cursor.execute("SELECT status FROM dns_records WHERE name = %s", (dns_name,))
        record = cursor.fetchone()
        if record and record[0] == new_status:
            return jsonify({"message": f"DNS {dns_name} is already {new_status}."})

        # Check if ad blocking (NextDNS) is active
        nextdns_status = subprocess.check_output(['nextdns', 'status'], stderr=subprocess.STDOUT).decode('utf-8').strip()
        if 'running' in nextdns_status:
            return jsonify({"message": "VaultGuard is on. Cannot update DNS while it is running."})

        # If new status is 'active', set all other DNS records to 'inactive'
        if new_status == 'Active':
            cursor.execute("UPDATE dns_records SET status = 'Not Active'")
            cursor.execute("UPDATE dns_records SET status = 'Active' WHERE name = %s", (dns_name,))
        else:
            cursor.execute("UPDATE dns_records SET status = 'Not Active' WHERE name = %s", (dns_name,))

        conn.commit()

        # Update system DNS settings if necessary
        if new_status == 'Active':
            cursor.execute("SELECT dns, backup_dns FROM dns_records WHERE name = %s", (dns_name,))
            record = cursor.fetchone()
            if record:
                primary_dns, backup_dns = record

                result = subprocess.run(["sudo","nmcli", "-t", "-f", "NAME", "con", "show", "--active"], capture_output=True, text=True, check=True)
                default_con = result.stdout.strip().split("\n")[0]

                # Update DNS settings using nmcli (NetworkManager)
                dns_string = f"{primary_dns},{backup_dns}" if backup_dns else primary_dns
                subprocess.run(["sudo","nmcli", "con", "mod", default_con, "ipv4.dns", dns_string], check=True)
                subprocess.run(["sudo","nmcli", "con", "up", default_con], check=True)
                #subprocess.run(["sudo","systemd-resolve", "--flush-caches"], check=True)
                insert_log("DNS", "Success", f"DNS {dns_name} status updated to {new_status}")

        return jsonify({"message": f"DNS {dns_name} status updated to {new_status}"})

    except Exception as e:
        insert_log("DNS", "Failure", f"Failed to update DNS status: {e}")
        return jsonify({"message": f"Failed to update DNS status: {e}"})

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def toggle_firewall_internal(turn_on):
    global ids_process, firewall_process

    if ids_process is None:
        if turn_on:
            # Activate the firewall
            subprocess.run(['sudo', 'ufw', 'enable'], check=True)
            firewall_process = True
            insert_log("Firewall", "Active", "Firewall turned on")
            return jsonify({"message": "Firewall turned on."})
        else:
            # Deactivate the firewall
            subprocess.run(['sudo', 'ufw', 'disable'], check=True)
            firewall_process = False
            insert_log("Firewall", "Not Active", "Firewall turned off")
            return jsonify({"message": "Firewall turned off."})
    else:
        flash("Firewall cannot be toggled when IDS process is active.")
        return jsonify({"error": "Firewall cannot be toggled when IDS process is active."})

    return jsonify({"message": "Firewall status could not be updated."})

def vpn_toggle_by_name(vpn_name, new_status):
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch the VPN ID based on the provided VPN name
        cursor.execute('SELECT id, name FROM vpns WHERE name = %s', (vpn_name,))
        vpn_data = cursor.fetchone()

        if not vpn_data:
            return jsonify({"message": f"No VPN found with name: {vpn_name}"})

        vpn_id, vpn_name = vpn_data

        # Deactivate all other VPNs first if activating one
        if new_status == 'Active':
            cursor.execute('UPDATE vpns SET status = "Not Active" WHERE id != %s', (vpn_id,))
            conn.commit()

        # Activate or deactivate the selected VPN via NetworkManager
        nmcli_command = ['nmcli', 'con', 'up' if new_status == 'Active' else 'down', vpn_name]
        subprocess.run(nmcli_command, check=True)

        # Update the status of the selected VPN in the database
        cursor.execute('UPDATE vpns SET status = %s WHERE id = %s', (new_status, vpn_id))
        conn.commit()

        insert_log("VPN", "Success", f"VPN {vpn_name} status updated to {new_status}")
        return jsonify({"message": f"VPN {vpn_name} status updated to {new_status}"})

    except subprocess.CalledProcessError as nmcli_error:
        return jsonify({"message": f"Failed to update VPN status with NetworkManager: {nmcli_error}"})

    except Exception as e:
        insert_log("VPN", "Failure", f"Failed to update VPN status: {e}")
        return jsonify({"message": f"Failed to update VPN status: {e}"})

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def dns_add_internal(name, dns, backup_dns):

    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        sql_insert_query = """
            INSERT INTO dns_records (name, dns, backup_dns)
            VALUES (%s, %s, %s)
        """
        record_tuple = (name, dns, backup_dns)
        cursor.execute(sql_insert_query, record_tuple)
        connection.commit()
        insert_log("DNS", "Success", f"DNS record '{name}' added")
        message = "DNS record added successfully."
    except mysql.connector.Error as error:
        insert_log("DNS Add", "Failure", f"Failed to add DNS record '{name}': {str(error)}")
        message = f"An error occurred: {str(error)}"
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return jsonify({"message": message})

# Function to edit DNS record internally
def dns_edit_internal(name, dns, backup_dns):

    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        update_query = """
            UPDATE dns_records
            SET dns = %s, backup_dns = %s
            WHERE name = %s
        """
        cursor.execute(update_query, (dns, backup_dns, name))
        connection.commit()
        insert_log("DNS", "Success", f"DNS record '{name}' updated")
        message = "DNS record updated successfully."
    except mysql.connector.Error as error:
        insert_log("DNS", "Failure", f"Failed to update DNS record '{name}': {str(error)}")
        message = f"An error occurred: {str(error)}"
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return jsonify({"message": message})
    
def dns_delete_internal(dns_name):

    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        delete_query = "DELETE FROM dns_records WHERE name = %s"
        cursor.execute(delete_query, (dns_name,))
        connection.commit()
        
        # Check if any record was deleted
        if cursor.rowcount > 0:
            insert_log("DNS", "Success", f"DNS record '{dns_name}' deleted")
            message = f"DNS record with name '{dns_name}' has been removed."
        else:
            insert_log("DNS", "Failure", f"No DNS called '{dns_name}'")
            message = "No DNS record found with that name."
            
    except mysql.connector.Error as error:
        insert_log("DNS", "Failure", f"Failed to delete DNS record '{dns_name}': {str(error)}")
        message = f"An error occurred: {str(error)}"
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return jsonify({"message": message})

def vpn_add_internal(vpn_name, vpn_server_choice, vpn_username, vpn_password):
    
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    server_mapping = {
        'australia': 'VPN/Australia.ovpn',
        'usa': 'VPN/USA.ovpn',
        'uk': 'VPN/UK.ovpn',
    }

    ovpn_file = server_mapping.get(vpn_server_choice.lower())
    default_vpn_name = os.path.splitext(os.path.basename(ovpn_file))[0]  # Extracts name without the .ovpn

    if ovpn_file and os.path.exists(ovpn_file):
        # Import VPN using nmcli
        cmd_import = ['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', ovpn_file]
        process_import = subprocess.run(cmd_import, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if process_import.returncode != 0:
            return jsonify({"message": f"Failed to add VPN: {process_import.stderr}"})

        # Rename the imported VPN connection to the user's desired name if it is different
        if default_vpn_name != vpn_name:
            cmd_rename = ['nmcli', 'connection', 'modify', default_vpn_name, 'connection.id', vpn_name]
            subprocess.run(cmd_rename, check=False)  # We don't check this command because nmcli doesn't provide useful output here

        # Set VPN username and password
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', f'username={vpn_username}'], check=False)
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', 'password-flags=0'], check=False)
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.secrets', f'password={vpn_password}'], check=False)

        # Add the new VPN record to the database
        connection = get_db_connection()  # Assume this is a function that connects to your database
        cursor = connection.cursor()
        try:
            cursor.execute(
                'INSERT INTO vpns (name, type, server, username, password) VALUES (%s, %s, %s, %s, %s)',
                (vpn_name, 'Nordvpn', vpn_server_choice, vpn_username, vpn_password)
            )
            connection.commit()
        except mysql.connector.Error as error:
            return jsonify({"message": f"Database error: {error}"})
        finally:
            cursor.close()
            connection.close()
        insert_log("VPN", "Success", f"VPN {vpn_name} added successfully")
        return jsonify({"message": "VPN added successfully!"})
    else:
        insert_log("VPN", "Failure", f"Failed to add VPN: {str(e)}")
        return jsonify({"message": "VPN server not found!"})

def vpn_edit_internal(current_name, **veds):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    # Fetch the current VPN details from the database for comparison
    cursor.execute("SELECT name, server, username, password FROM vpns WHERE name = %s", (current_name,))
    vpn = cursor.fetchone()

    if not vpn:
        cursor.close()
        connection.close()
        return jsonify({"message": "VPN not found!"})

    server_mapping = {
        'australia': 'VPN/Australia.ovpn',
        'usa': 'VPN/USA.ovpn',
        'uk': 'VPN/UK.ovpn',
    }

    try:
        if 'new_server' in veds and veds['new_server'] != vpn[1]:
            # Delete the existing VPN connection
            subprocess.run(['nmcli', 'connection', 'delete', current_name], check=True)
            
            # Add the new VPN connection using the .ovpn file
            new_ovpn_file = server_mapping.get(veds['new_server'].lower())
            default_vpn_name = os.path.splitext(os.path.basename(ovpn_file))[0]

            if new_ovpn_file and os.path.exists(new_ovpn_file):
                subprocess.run(['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', new_ovpn_file], check=True)

                # If there's a new name, rename the VPN connection
                if 'new_name' in veds:
                    subprocess.run(['nmcli', 'connection', 'modify', default_vpn_name, 'connection.id', veds['new_name']], check=True)
                else:
                    subprocess.run(['nmcli', 'connection', 'modify', default_vpn_name, 'connection.id', current_name], check=True)

            # Set username and password if provided
            if 'new_username' in veds:
                subprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.data', f'username={veds["new_username"]}'], check=True)
            else:
                ubprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.data', f'username={vpn[2]}'], check=True)

            if 'new_password' in veds:
                subprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.data', 'password-flags=0'], check=True)
                subprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.secrets', f'password={veds["new_password"]}'], check=True)
            else:
                subprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.data', 'password-flags=0'], check=True)
                subprocess.run(['nmcli', 'connection', 'modify', veds.get('new_name', current_name), '+vpn.secrets', f'password={vpn[3]}'], check=True)
        else:
            # Handle changes that don't require recreating the VPN connection
            if 'new_name' in veds and veds['new_name'] != current_name:
                subprocess.run(['nmcli', 'connection', 'modify', current_name, 'connection.id', veds['new_name']], check=True)

            if 'new_username' in veds and veds['new_username'] != vpn[2]:
                subprocess.run(['nmcli', 'connection', 'modify', current_name, '+vpn.data', f'username={veds["new_username"]}'], check=True)

            if 'new_password' in veds and veds['new_password'] != vpn[3]:
                subprocess.run(['nmcli', 'connection', 'modify', current_name, '+vpn.data', 'password-flags=0'], check=True)
                subprocess.run(['nmcli', 'connection', 'modify', current_name, '+vpn.secrets', f'password={veds["new_password"]}'], check=True)

        # Update the database record with new details if provided
        updated_name = veds.get('new_name', vpn[0])
        updated_server = veds.get('new_server', vpn[1])
        updated_username = veds.get('new_username', vpn[2])
        updated_password = veds.get('new_password', vpn[3])

        cursor.execute(
            "UPDATE vpns SET name = %s, server = %s, username = %s, password = %s WHERE name = %s",
            (updated_name, updated_server, updated_username, updated_password, current_name)
        )
        connection.commit()

    except subprocess.CalledProcessError as e:
        # Rollback the database update in case of an error
        connection.rollback()
        insert_log("VPN", "Failure", f"Failed to edit VPN: {str(e)}")
        return jsonify({"message": f"An error occurred: {e}"})
    finally:
        cursor.close()
        connection.close()

    insert_log("VPN", "Success", f"VPN {current_name} edited successfully")
    return jsonify({"message": "VPN updated successfully!"})

def vpn_delete_internal(vpn_name):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    if 'loggedin' not in session:
        return jsonify({"message": "User not logged in"})
        
    try:
        # Attempt to delete the VPN from the database first
        cursor.execute("DELETE FROM vpns WHERE name = %s", (vpn_name,))
        rows_deleted = cursor.rowcount
        connection.commit()

        # If the VPN was found and deleted from the database, delete from nmcli
        if rows_deleted > 0:
            subprocess.run(['nmcli', 'connection', 'delete', vpn_name], check=True)
            insert_log("VPN", "Success", f"VPN {vpn_name} deleted successfully")
            message = "VPN deleted successfully!"
        else:
            message = "VPN not found!"
    except subprocess.CalledProcessError as e:
        # If nmcli deletion fails, roll back the database deletion
        connection.rollback()
        message = f"Failed to delete VPN: {e}"
    except mysql.connector.Error as e:
        # Handle any database errors that occur
        insert_log("VPN", "Failure", f"Failed to delete VPN: {str(e)}")
        message = f"Database error: {e}"
    finally:
        cursor.close()
        connection.close()
        return jsonify({"message": message})

@app.route('/restart-cybervaultapp')
def restart_cybervaultapp():
    # Check if the user is logged in
    if 'loggedin' not in session:
        # Respond with an error message and a redirect URL
        return jsonify({"error": "User not logged in", "redirect": url_for('login')}), 401

    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'cybervaultapp'], check=True)
    except subprocess.CalledProcessError as e:
        # Handle errors if the command failed
        return jsonify({"error": str(e)})

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'loggedin' not in session:
        return redirect('/login')
        
    if request.method == 'POST':
        try:
            # Get the timeout value from the form and convert it to an integer
            stime = int(request.form['timeout'])
            # Update the session lifetime
            app.permanent_session_lifetime = dt.timedelta(minutes=stime)
            insert_log("Settings", "Success", f"Session timeout updated to {stime} minutes")
            flash('Session timeout has been updated.')
        except (ValueError, KeyError):
            # If the form doesn't submit a valid timeout value
            flash('Invalid session timeout value.')
            insert_log("Settings", "Failure", f"Failed to update session timeout")
    # Whether it's a POST or GET request, render settings.html
    # The form will show the current session timeout (even the default one)
    current_timeout = app.permanent_session_lifetime // dt.timedelta(minutes=1)
    return render_template('settings.html', current_timeout=current_timeout)
         
#Allows the user to configure the wifi connection, currently only supports WPA-2 because of its simplicity         
@app.route('/wifisetup', methods=['GET', 'POST'])
def wifisetup():
    if request.method == 'POST':
        ssid = request.form.get('ssid')
        password = request.form.get('password')

        # Check if SSID or password is not provided or empty
        if not ssid or not password:
            flash('SSID and password are required.')
            return redirect(url_for('wifisetup'))

        # Try to delete any existing connection with the same SSID
        try:
            existing_con = subprocess.run(['nmcli', 'con', 'show'], stdout=subprocess.PIPE, text=True)
            if ssid in existing_con.stdout:
                delete_con = subprocess.run(['sudo','nmcli', 'con', 'delete', ssid], check=True)
        except subprocess.CalledProcessError as e:
            flash(f'Failed to delete existing Wi-Fi connection: {e}')

        # Connect to the Wi-Fi using nmcli
        try:
            subprocess.run(['sudo', 'nmcli', 'dev', 'wifi', 'connect', ssid, 'password', password], check=True)
            # Update the Wi-Fi details into the database
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("DELETE FROM wifi")  # Clear the table before inserting new entry
            cursor.execute("INSERT INTO wifi (ssid, password) VALUES (%s, %s)", (ssid, password))
            connection.commit()
            cursor.close()
            connection.close()
            insert_log("Wi-Fi", "Success", f"Connected to Wi-Fi SSID {ssid} successfully")
            flash('Connected to Wi-Fi and updated settings successfully.')
        except subprocess.CalledProcessError as e:
            flash(f'Failed to connect to Wi-Fi: {e}')
            insert_log("Wi-Fi", "Failure", f"Failed to connect to Wi-Fi SSID {ssid}: {str(e)}")
            if 'connection' in locals():
                connection.rollback()

        return redirect(url_for('wifisetup'))


    else:
        available_ssids = []
        if request.method == 'GET':
            # Scan for Wi-Fi networks
            try:
                scan_result = subprocess.run(['nmcli', '-f', 'SSID,SECURITY', 'dev', 'wifi'], stdout=subprocess.PIPE, text=True, check=True)
                for line in scan_result.stdout.splitlines():
                    if "WPA" in line:
                        ssid = re.search(r'^(.*?)\s{2,}', line)
                        if ssid:
                            available_ssids.append(ssid.group(1).strip())
            except subprocess.CalledProcessError as e:
                flash(f'Failed to scan Wi-Fi networks: {e}')

        return render_template('wifisetup.html', available_ssids=available_ssids)

@app.route('/logs')
def logs():
    if 'loggedin' not in session:
        return redirect('/login')
        
    # Fetching logs from the database
    logs_query = "SELECT * FROM Logs ORDER BY logTime DESC"
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(logs_query)
    logs_data = cursor.fetchall()
    cursor.close()
    connection.close()

    # Passing logs data to the template
    return render_template('logs.html', logs=logs_data)


@app.route('/ids')
def IDS():
    if 'loggedin' not in session:
        return redirect('/login')
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT attackType, actionTaken, eventID FROM IDS ORDER BY eventID DESC')
    IDS = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return render_template('ids.html', ids_records=IDS)


@app.route('/revert_block/<int:event_id>', methods=['POST'])
def revert_block(event_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)

        # Get the IDS record for the specified event_id
        query = "SELECT eventID, attackIP, actionTaken, attackType FROM IDS WHERE eventID = %s"
        cursor.execute(query, (event_id,))
        ids_record = cursor.fetchone()

        if ids_record:
            attack_ip = ids_record['attackIP']
            action = ids_record['actionTaken']
            attack_type = ids_record['attackType']
            
            if action == "None":
            	subprocess.run(['sudo', 'ufw', 'deny', 'from', attack_ip])
            	ids_query = "UPDATE IDS SET eventTime = %s, actionTaken = %s WHERE eventID = %s"
            	ids_data = (dt.datetime.now(), f"{attack_ip} Blocked by User", event_id)
            	fw_query = "INSERT INTO Firewall (eventIP, status) VALUES (%s, %s)"
            	fw_data = (attack_ip, "Blocked by User")
            	cursor.execute(ids_query, ids_data)
            	cursor.execute(fw_query, fw_data)
            	
		# Insert into Logs table
            	log_query = "INSERT INTO Logs (logType, logTime, logStatus, logDescription) VALUES (%s, %s, %s, %s)"
            	log_data = ("IDS", dt.datetime.now(), "Blocked by User", f"{attack_ip} Blocked by User")
            	cursor.execute(log_query, log_data)

            	conn.commit()

            	return jsonify({"success": True, "message": "Block successful."})
            
            else:	 
            	subprocess.run(['sudo', 'ufw', 'delete', 'deny', 'from', attack_ip])
            	description = f"Unblocked {attack_ip}"

            	# Delete IDS record
            	cursor.execute("DELETE FROM IDS WHERE eventID = %s", (event_id,))

            	# Delete Firewall record
            	cursor.execute("DELETE FROM Firewall WHERE eventIP = %s", (attack_ip,))

            	# Insert into Logs table
            	log_query = "INSERT INTO Logs (logType, logTime, logStatus, logDescription) VALUES (%s, %s, %s, %s)"
            	log_data = ("Revert", dt.datetime.now(), "Reverted", f"Unblocked {attack_ip}")
            	cursor.execute(log_query, log_data)

            	conn.commit()

            	return jsonify({"success": True, "message": "Revert successful."})
        else:
            return jsonify({"error": "IDS record not found."})
    except Exception as e:
    	print(str(e))
    	return jsonify({"error": str(e)})
    finally:
    	cursor.close()
    	conn.close()

#Function that is used to update the IDS page with auto-refresh when a new alert is added        
def check_ids_count():
    if 'loggedin' not in session:
        return redirect('/login')

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # SQL query to count the number of entries in the IDS table
    cursor.execute('SELECT COUNT(*) FROM IDS')
    count = cursor.fetchone()[0]
    
    cursor.close()
    conn.close()

    return count
    
@app.route('/check-ids-update')
def check_ids_update():
    count = check_ids_count()
    # Assuming count is a number or a redirect response
    if isinstance(count, int):
        return jsonify({"count": count})
    return count


@app.route('/IDS_set_mode', methods=['POST'])
def IDS_set_mode():
    global ids_mode
    new_mode = request.form.get('mode')
    insert_log("IDS", "Mode Change", f"IDS mode changed to {new_mode}")
    ids_mode = new_mode
    return jsonify({"message": "IDS mode updated."})

@app.route('/IDS_toggle_status', methods=['POST'])
def toggle_status():
    global ids_status, ids_process, firewall_process
    try:
        if ids_status:
            if ids_process is not None:
                ids_process.kill()
                ids_process = None
                insert_log("IDS", "Not Active", "IDS turned off")
        else:
            ids_process = subprocess.Popen(['sudo', 'python3', 'Cybervault_Capture_ufw.py'])
            insert_log("IDS", "Active", "IDS turned on")
            if not firewall_process:
                firewall_process = True
                subprocess.run(['sudo', 'ufw', 'enable'], check=True)
                insert_log("IDS", "Firewall Active", "Firewall turned on")

        ids_status = not ids_status
        return jsonify({"message": "IDS status updated."})
    except Exception as e:
        # Log the exception for debugging
        logger.error(f"An error occurred in toggle_status: {str(e)}")
        return jsonify({"error": "An error occurred while updating IDS status."}), 500

@app.route('/IDS_get_mode')
def IDS_get_mode():
    return jsonify({"mode": ids_mode})
    
@app.route('/IDS_get_status')
def IDS_get_status():
    return jsonify({"status": ids_status, "mode": ids_mode})

@app.route('/get_ids_process_status')
def get_ids_process_status():
    global ids_process
    return jsonify({"is_none": ids_process is None})

#Function that supports the VaultGuard analytics backend by making API calls to fetch data
def get_nextdns_analytics():
    headers = {"X-Api-Key": NEXTDNS_API_KEY}

    try:
        # Fetch most blocked domain
        domains_url = f"{NEXTDNS_BASE_URL}{NEXTDNS_PROFILE_ID}/analytics/domains?limit=1&status=blocked"
        domains_response = requests.get(domains_url, headers=headers).json()
        most_blocked_domain = domains_response['data'][0]['domain']

        # Fetch blocked status count
        status_url = f"{NEXTDNS_BASE_URL}{NEXTDNS_PROFILE_ID}/analytics/status"
        status_response = requests.get(status_url, headers=headers).json()
        blocked_queries = next((item for item in status_response['data'] if item["status"] == "blocked"), {}).get('queries', 0)

        total_queries = sum(item['queries'] for item in status_response['data'])
        blocked_ratio = f"{(blocked_queries / total_queries * 100):.2f}%" if total_queries else "0%"

    except Exception as e:
        print(f"Error: {e}")
        most_blocked_domain, blocked_ratio, blocked_queries = "Unavailable", "0%", 0

    return most_blocked_domain, blocked_ratio, blocked_queries


@app.route('/firewall')
def firewall():
    if 'loggedin' not in session:
        return redirect('/login')

    most_blocked_domain, blocked_ratio, blocked_count = get_nextdns_analytics()

    return render_template('firewall.html', most_blocked_domain=most_blocked_domain, blocked_ratio=blocked_ratio, blocked_count=blocked_count)
    
#This is the VaultGuard function that enables NextDNS which has our configuration setup    
@app.route('/activatenextdns', methods=['POST'])
def activatenextdns():
    nextdns_status = subprocess.check_output(['nextdns', 'status'], stderr=subprocess.STDOUT).decode('utf-8').strip()

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        if 'running' in nextdns_status:
            subprocess.run(['sudo','nextdns', 'stop'], check=True)
            subprocess.run(['sudo','nextdns', 'deactivate'], check=True)
            new_status = 'Not Active'
        else:
            subprocess.run(['sudo','nextdns', 'activate'], check=True)
            subprocess.run(['sudo','nextdns', 'start'], check=True)
            new_status = 'Active'

            # Set any 'Active' status in dns_records table to 'Not Active'
            cursor.execute("UPDATE dns_records SET status = 'Not Active' WHERE status = 'Active'")
            connection.commit()

        return jsonify({'success': True, 'status': new_status})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': 'Command failed: ' + str(e) + ' Output: ' + e.output.decode()})
    except mysql.connector.Error as db_error:
        return jsonify({'success': False, 'error': 'Database error: ' + str(db_error)})
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/nextdnsstatus', methods=['GET'])
def nextdnsstatus():
    nextdns_status = subprocess.check_output(['nextdns', 'status'], stderr=subprocess.STDOUT).decode('utf-8').strip()

    try:
        return jsonify({'status': 'Active' if 'running' in nextdns_status else 'Not Active'})
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'Error checking status: ' + e.output.decode()})

@app.route('/toggle_firewall_status', methods=['POST'])
def toggle_firewall_status():
    global ids_process, firewall_process
    if 'loggedin' not in session:
        return jsonify({"error": "User not logged in"}) 

    if ids_process is None:
        if firewall_process is False:
            # Activate the firewall
            subprocess.run(['sudo', 'ufw', 'enable'], check=True)
            firewall_process = True
            insert_log("Firewall", "Active", "Firewall turned on")
        else:
            # Deactivate the firewall
            subprocess.run(['sudo', 'ufw', 'disable'], check=True)
            firewall_process = False
            insert_log("Firewall", "Not Active", "Firewall turned off")
    else:
        flash("Firewall cannot be toggled when IDS process is active.")
        return jsonify({"error": "Firewall cannot be toggled when IDS process is active."})

    return jsonify({"message": "Firewall status updated."})

#Function for bandwidth graph    
def get_network_stats():
    # Getting initial stats
    initial_stats = psutil.net_io_counters()
    initial_bytes_sent = initial_stats.bytes_sent
    initial_bytes_recv = initial_stats.bytes_recv

    # Waiting for a second to calculate the speed
    time.sleep(1)

    # Getting updated stats after 1 second
    updated_stats = psutil.net_io_counters()
    updated_bytes_sent = updated_stats.bytes_sent
    updated_bytes_recv = updated_stats.bytes_recv

    # Calculating bytes sent and received in the last second
    bytes_sent = updated_bytes_sent - initial_bytes_sent
    bytes_recv = updated_bytes_recv - initial_bytes_recv

    return bytes_sent, bytes_recv
    
@app.route('/network-data')
def network_data():
    if 'loggedin' not in session:
        return jsonify({"error": "User not logged in"}), 401  # 401 Unauthorized

    bytes_sent, bytes_recv = get_network_stats()
    return jsonify({
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_recv
    })

if __name__ == "__main__":
    app.run(ssl_context=('self-signed.crt', 'private.key'), debug=True)

#if __name__ == "__main__":
    #app.run(host='10.42.0.1', port=5000, ssl_context=('self-signed.crt', 'private.key'), debug=True)

