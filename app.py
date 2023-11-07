from flask import Flask, request, redirect, session, render_template, flash,jsonify,url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
import subprocess
import openai
from flask_talisman import Talisman

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = datetime.timedelta(minutes=5)
openai.api_key = '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'
Talisman(app, content_security_policy=None)

db_config = {
    'host': 'localhost',
    'user': 'cybervault_user',
    'password': 'your_password',
    'database': 'cybervault_db'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/')
def index():
    if 'loggedin' in session:
        # If the user is logged in, render the index.html
        return render_template('index.html', username=session['username'])
    # If not logged in, redirect to the login page
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
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
            return redirect('/')
        else:
            flash('Incorrect username/password!')
    return render_template('login.html')

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
        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
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
            return redirect('/login')
        else:
            flash("Invalid username or security answer.")

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
            flash("Password has been updated.")
            return redirect('/login')
        else:
            flash("Invalid username or password.")

        cursor.close()
        conn.close()

    return render_template('reset.html')



@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    return redirect('/login')
    
    

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=5)
    
@app.route('/dns-over-httpsdis')
def dns_over_https():
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
    
@app.route('/dns-add', methods=['GET', 'POST'])
def dns_add():
    if request.method == 'POST':
    
        name = request.form.get('name')
        dns = request.form.get('dns')
        backup_dns = request.form.get('backup_dns')

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
        except mysql.connector.Error as e:
            # Error handling logic
            pass
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

        # Redirect or show success message
        return redirect('/dns-over-httpsdis')  # Adjust as needed

    return render_template('dns-add.html')


@app.route('/update_status', methods=['POST'])
def update_status():
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
            result = subprocess.run(["nmcli", "-t", "-f", "NAME", "con", "show", "--active"], capture_output=True, text=True, check=True)
            default_con = result.stdout.strip().split("\n")[0]

            # Update DNS settings using nmcli
            dns_string = f"{primary_dns},{backup_dns}" if backup_dns else primary_dns
            subprocess.run(["nmcli", "con", "mod", default_con, "ipv4.dns", dns_string], check=True)
            subprocess.run(["nmcli", "con", "up", default_con], check=True)

    except mysql.connector.Error as error:
        return jsonify({'success': False, 'error': str(error)})
    except subprocess.CalledProcessError as sp_error:
        return jsonify({'success': False, 'error': str(sp_error)})
    finally:
        cursor.close()
        connection.close()

    return jsonify({'success': True})
    
@app.route('/dns-edit/<int:dns_id>', methods=['GET', 'POST'])
def dns_edit(dns_id):
    connection = get_db_connection()
    cursor = connection.cursor(buffered=True)

    if request.method == 'POST':
        # Get data from form
        name = request.form['name']
        dns = request.form['dns']
        backup_dns = request.form['backup_dns']

        # Update record in the database
        update_query = """
            UPDATE dns_records
            SET name = %s, dns = %s, backup_dns = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (name, dns, backup_dns, dns_id))
        connection.commit()

        cursor.close()
        connection.close()

        return redirect('/dns-over-httpsdis')

    # For a GET request, fetch the existing data to prefill the form
    try:
        cursor.execute("SELECT id,name, dns, backup_dns FROM dns_records WHERE id = %s", (dns_id,))
        record = cursor.fetchone()
    except mysql.connector.Error as e:
        record = None  # Or handle error as required
    finally:
        cursor.close()
        connection.close()

    # Redirect to the edit form with existing data
    return render_template('dn-sedit.html', record=record)

@app.route('/chatbot-system')
def chatbot_system():
    return render_template('chatbotsystem.html')
    
@app.route('/chatbot-discovery')
def chatbot_disovery():
    return render_template('chatbotdiscovery.html')
    
@app.route('/send_message_discovery', methods=['POST'])
def send_message_discovery():
    user_message = request.json['message']

    # Define the context or introduction for the conversation
    intro_context = (
        "You are an assistant specialized in cybersecurity, focusing on topics "
        "like home and network security. Provide helpful and accurate information "
        "on these subjects. If the user asks questions that not related to this, inform them that you are only trained to assist in cybersecurity."
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
    
        
@app.route('/vpn')
def vpn():
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

@app.route('/update_vpn_status', methods=['POST'])
def update_vpn_status():
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

        return jsonify({'success': True})

    except subprocess.CalledProcessError as nmcli_error:
        # Handle errors from nmcli
        return jsonify({'success': False, 'error': 'Failed to update VPN status with NetworkManager: ' + str(nmcli_error)})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        


@app.route('/vpn-add', methods=['GET', 'POST'])
def vpn_add():
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

        if vpn_type.lower() == 'nordvpn':
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
                    flash(f"Database error: {error}")
                    return redirect('/vpn-add')
                finally:
                    cursor.close()
                    connection.close()

                flash('VPN added successfully!')
                return redirect('/vpn')
            else:
                flash('Server .ovpn file does not exist.')
                return redirect('/vpn-add')
        else:
            flash('Unsupported VPN type.')
            return redirect('/vpn-add')

    else:
        return render_template('vpn-add.html')


@app.route('/vpn-edit/<int:vpn_id>', methods=['GET', 'POST'])
def vpn_edit(vpn_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    # POST: Update the VPN record
    if request.method == 'POST':
        # Extract data from form
        new_name = request.form['name']
        new_type = request.form['type']
        new_server = request.form['server']
        new_username = request.form['username']
        new_password = request.form['password']

        # Fetch the current VPN details from the database for comparison
        cursor.execute("SELECT * FROM vpns WHERE id = %s", (vpn_id,))
        vpn = cursor.fetchone()

        if vpn:
            # Update the VPN connection if the name has changed
            if vpn[1] != new_name:
                rename_command = ['nmcli', 'connection', 'modify', vpn[1], 'connection.id', new_name]
                process = subprocess.run(rename_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if process.returncode != 0:
                    flash(f"Failed to rename VPN: {process.stderr}")
                    cursor.close()
                    connection.close()
                    return redirect(url_for('vpn_edit', vpn_id=vpn_id))
                    
            if vpn[2] != new_username:
                subprocess.run(['nmcli', 'connection', 'modify', vpn[1], 'vpn.data', f'username={new_username}'], check=False)

            if vpn[3] != new_password:
                subprocess.run(['nmcli', 'connection', 'modify', vpn[1], 'vpn.data', 'password-flags=0'], check=False)
                subprocess.run(['nmcli', 'connection', 'modify', vpn[1], 'vpn.secrets', f'password={new_password}'], check=False)

            # Update other properties and handle VPN type change if needed here
	
            # Update the database record
            update_query = """
                UPDATE vpns SET
                name = %s,
                type = %s,
                server = %s,
                username = %s,
                password = %s
                WHERE id = %s
            """
            cursor.execute(update_query, (new_name, new_type, new_server, new_username, new_password, vpn_id))
            connection.commit()
            flash('VPN updated successfully!')
        else:
            flash('VPN not found!')

        cursor.close()
        connection.close()
        return redirect('/vpn') 

    # GET: Render the form with pre-filled data
    else:
        cursor.execute("SELECT * FROM vpns WHERE id = %s", (vpn_id,))
        vpn = cursor.fetchone()
        cursor.close()
        connection.close()

        if vpn:
            return render_template('vpn-edit.html', vpn=vpn)  # Ensure 'vpn-edit.html' is the correct template name
        else:
            flash('VPN not found!')
            return redirect(url_for('vpn_edit', vpn_id=vpn_id))  

@app.route('/send_message_system', methods=['POST'])
def send_message_system():
    user_message = request.json['message']
    conversation_history = session.get('conversation_history', [])

    # Add the new user message to the conversation history
    conversation_history.append({"role": "user", "content": user_message})

    # Define the context or introduction for the conversation
    intro_context = (
        "You are an AI assistant specialized in DNS and VPN management tasks such as adding, "
        "editing, and removing DNS records and VPN configurations. When provided with the necessary details for a DNS or VPN task, "
        "you will respond with a simple templated message indicating the action to take. For DNS management, "
        "for example, 'Action: Add - name: example, dns: 1.1.1.1, backup_dns: 2.2.2.2'. To edit a DNS record, "
        "respond with 'Action: Edit - name: example, dns: 1.1.1.1, backup_dns: 2.2.2.2'. To delete a DNS record, "
        "respond with 'Action: Delete - name: example.com'. For VPN management, to add a VPN, respond with "
        "'Action: Add VPN - name: exampleVPN, server: USA, username: user123, password: pass123'. To edit a VPN, "
        "respond with 'Action: Edit VPN - id: 1, name: newExampleVPN, server: UK, username: newuser123, password: newpass123'. "
        "Do not provide steps or ask for confirmations, just the action and the details. If the details are not provided in this format, "
        "you will ask the user to provide them accordingly."
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
            action_part, params_part = bot_message.split(" - ")
            
            # Clear the conversation history after performing an action
            session.pop('conversation_history', None)

            if action_part.startswith('Action: Add'):
                param_dict = {param.split(": ")[0]: param.split(": ")[1] for param in params_part.split(", ")}
                response = dns_add_internal(param_dict['name'], param_dict['dns'], param_dict['backup_dns'])
                return response
            elif action_part.startswith('Action: Edit'):
                param_dict = {param.split(": ")[0]: param.split(": ")[1] for param in params_part.split(", ")}
                response = dns_edit_internal(param_dict['name'], param_dict['dns'], param_dict['backup_dns'])
                return response
            elif action_part.startswith('Action: Delete'):
                # Assuming that the bot_message for delete would be 'Action: Delete - name: example.com'
                dns_name = params_part.split(": ")[1].strip()
                response = dns_delete_internal(dns_name)
                return response
            elif action_part.startswith('Action: Add VPN'):
                param_dict = {param.split(": ")[0]: param.split(": ")[1] for param in params_part.split(", ")}
                response = vpn_add_internal(param_dict['name'], param_dict['server'], param_dict['username'], param_dict['password'])
                return response
            elif action_part.startswith('Action: Edit VPN'):
                vpn_id = params_part.split(": ")[1].strip()  # Adjust this depending on the bot's response format
                param_dict = {param.split(": ")[0]: param.split(": ")[1] for param in params_part.split(", ")}
                response = vpn_edit_internal(vpn_id, param_dict['name'], param_dict['server'], param_dict['username'], param_dict['password'])
                return response
                # Add other actions if necessary
        except IndexError:
            # Handle the case where the bot's message isn't in the expected format
            return jsonify({"reply": "There was an error processing the action. Please try again."})
        except KeyError as e:
            # Handle the case where expected parameters are missing
            return jsonify({"reply": f"Missing parameter: {e}. Please provide all required details."})
    else:
        # If the response is a question or not an action, return the bot's message to ask for more information
        return jsonify({"reply": bot_message})

def dns_add_internal(name, dns, backup_dns):
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
        message = "DNS record added successfully."
    except mysql.connector.Error as error:
        message = f"An error occurred: {str(error)}"
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return jsonify({"message": message})

# Function to edit DNS record internally
def dns_edit_internal(name, dns, backup_dns):
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
        message = "DNS record updated successfully."
    except mysql.connector.Error as error:
        message = f"An error occurred: {str(error)}"
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return jsonify({"message": message})
    
def dns_delete_internal(dns_name):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        delete_query = "DELETE FROM dns_records WHERE name = %s"
        cursor.execute(delete_query, (dns_name,))
        connection.commit()
        
        # Check if any record was deleted
        if cursor.rowcount > 0:
            message = f"DNS record with name '{dns_name}' has been removed."
        else:
            message = "No DNS record found with that name."
            
    except mysql.connector.Error as error:
        message = f"An error occurred: {str(error)}"
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return jsonify({"message": message})

def vpn_add_internal(vpn_name, vpn_server_choice, vpn_username, vpn_password):
    server_mapping = {
        'australia': 'VPN/Australia.ovpn',
        'usa': 'VPN/USA.ovpn',
        'uk': 'VPN/UK.ovpn',
    }

    ovpn_file = server_mapping.get(vpn_server_choice.lower())

    if ovpn_file and os.path.exists(ovpn_file):
        # Import VPN using nmcli
        cmd_import = ['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', ovpn_file]
        process_import = subprocess.run(cmd_import, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if process_import.returncode != 0:
            return f"Failed to add VPN: {process_import.stderr}"

        # Set VPN username and password
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', f'username={vpn_username}'], check=False)
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.data', 'password-flags=0'], check=False)
        subprocess.run(['nmcli', 'connection', 'modify', vpn_name, '+vpn.secrets', f'password={vpn_password}'], check=False)

        # Add the new VPN record to the database
        connection = get_db_connection()  # Assume this is a function that connects to your database
        cursor = connection.cursor()
        try:
            cursor.execute(
                'INSERT INTO vpns (name, server, username, password) VALUES (%s, %s, %s, %s)',
                (vpn_name, vpn_server_choice, vpn_username, vpn_password)
            )
            connection.commit()
        except mysql.connector.Error as error:
            return f"Database error: {error}"
        finally:
            cursor.close()
            connection.close()

        return jsonify({"message": "VPN added successfully!"})
    else:
        return jsonify({"message": "VPN server not found!"})

def vpn_edit_internal(vpn_name, new_name, new_server, new_username, new_password):
    # Logic similar to the '/vpn-edit' route, adjusted for finding VPN by name
    connection = get_db_connection()
    cursor = connection.cursor()
    
    # Fetch the current VPN details from the database for comparison
    cursor.execute("SELECT * FROM vpns WHERE name = %s", (vpn_name,))
    vpn = cursor.fetchone()

    if vpn:
        # Update the VPN connection if any detail has changed
        if vpn[1] != new_name:
            rename_vpn_connection(new_name, vpn[1])
        if vpn[3] != new_username:
            update_vpn_username(new_name, new_username)
        if vpn[4] != new_password:
            update_vpn_password(new_name, new_password)
        update_vpn_server(new_name, new_server)
        
        # Update the database record
        cursor.execute(
            "UPDATE vpns SET name = %s, server = %s, username = %s, password = %s WHERE name = %s",
            (new_name, new_server, new_username, new_password, vpn_name)
        )
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"message": "VPN updated successfully!"})
    else:
        cursor.close()
        connection.close()
        return jsonify({"message": "VPN not found!"})
            
if __name__ == "__main__":
    app.run(ssl_context=('self-signed.crt', 'private.key'), debug=True)

