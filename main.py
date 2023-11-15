import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

import pymysql
from flask import Flask, render_template, url_for, json, session, jsonify
from flask import request as reqf
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_mail import Mail, Message
from werkzeug.utils import redirect


app = Flask(__name__)
app.secret_key = 'dGhpc2lzbXlhcHBzZWNyZWF0a2V5'


app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sonacloud@sonatech.ac.in'
app.config['MAIL_PASSWORD'] = 'G4b$Sd7QJZaHbNJ'
app.config['MAIL_DEFAULT_SENDER'] = 'sonacloud@sonatech.ac.in'

mail = Mail(app)

host = 'localhost'  # Replace with your MySQL host
user = 'root'  # Replace with your MySQL username
password = ''  # Replace with your MySQL password
database = 'users'  # Replace with your MySQL database name
baseurl = 'http://172.16.23.5:8080/client/api?'
secretkey = 'dmKJEDmijUYC6V53mpQZzNipzPryi0lizIYx9dvCepifE4XhcwkLX7W7txruiRaXkPHwadnl4lFGSVTUD7Ho_w'
api_key = 'CN9MeFkRSP09yNJ8d4W1GxLrBJEvGUATpipIpzu9GA6MC6SxNI-1ixRLjX2eANF6znPzZ1n0Unzc5OjqHEwRZA'


def create_connection():
    connection = pymysql.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor  # Optional: Use DictCursor for dictionary-based results
    )
    return connection


login_manager = LoginManager(app)
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, user):
        self.regno = user['reg_no']
        self.name = user['name']
        self.email = user['email']
        self.dept = user['department']
        self.is_admin = user['is_admin'] == 1

    def get_id(self):
        return str(self.regno)


@login_manager.user_loader
def load_user(regno):
    connection = create_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM user WHERE reg_no = %s"
        cursor.execute(sql, (regno,))
        user = cursor.fetchone()
        if user:
            return User(user)
    return None


def generate_verification_token():
    # Generate a random token using secrets module
    token = secrets.token_hex(16)
    return token


def send_api_request(request):
    request_str = urllib.parse.urlencode(request)

    sig_str = '&'.join(['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
                        sorted(request.keys())])
    sig = base64.b64encode(hmac.new(secretkey.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
        'utf-8')
    req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)
    with urllib.request.urlopen(req) as response:
        res = response.read().decode('utf-8')
    return res


@app.route('/admin/approvedvm')
@login_required
def list_approved_vm():
    connection = create_connection()
    try:
        with connection.cursor() as cursor:
            sql = "SELECT t1.*, t2.* FROM vm t1 JOIN request_vm t2 ON t1.reg_no = " \
                  "t2.reg_no"
            # Replace with your table name
            cursor.execute(sql)
            data = cursor.fetchall()
            print(data)
    finally:
        connection.close()
    return render_template('approvedvm.html', data=data)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect('/admin')
        # Redirect logged-in users to a different page
        return redirect(url_for('user_dashboard'))
    if reqf.method == 'POST':
        # Get the user data from the form
        name = reqf.form['name']
        email = reqf.form['email']
        regno = reqf.form['regno']
        dept = reqf.form['department']
        user_password = reqf.form['password']
        print(regno)
        # Generate a verification token
        token = generate_verification_token()
        # Send the verification email
        send_verification_email(name, email, token)
        # Save the user details and token to the database
        save_user_to_database(name, email, token, regno, user_password, dept)
        # Redirect the user to a verification page or show a success message
        return redirect('/verify')

    return render_template('register.html')


@app.route('/verify')
def verification_page():
    return render_template('verify.html')


def save_user_to_database(name, email, token, regno, user_password, dept):
    connection = create_connection()
    cursor = connection.cursor()

    # Execute the insert query
    sql = "INSERT INTO user (name, email, verification_token, reg_no, password, department) VALUES (%s, %s, %s,%s,%s," \
          "%s)"
    cursor.execute(sql, (name, email, token, regno, user_password, dept))

    # Commit the changes to the database
    connection.commit()

    # Close the cursor
    cursor.close()


@app.route('/verify_email/<token>')
def verify_email(token):
    # Verify the token and update the user's status in the database
    update_user_status(token)
    # Redirect the user to a success page or show a success message
    return redirect(url_for('login'))


def update_user_status(token):
    connection = create_connection()  # Create a connection to your database

    try:
        with connection.cursor() as cursor:
            # Retrieve the user based on the verification token
            sql = "SELECT * FROM user WHERE verification_token = %s"
            cursor.execute(sql, (token,))
            user = cursor.fetchone()

            if user:
                # Update the user's status to indicate verification
                sql = "UPDATE user SET status = 'verified' WHERE reg_no = %s"
                cursor.execute(sql, (user['reg_no'],))
                connection.commit()  # Commit the changes to the database
            else:
                # Handle the case when the user is not found or the token is invalid
                pass
    finally:
        connection.close()  # Close the database connection


def send_verification_email(name, email, token):
    subject = 'SPC Account Activation'
    body = f'''
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.5;
            }}
            h1 {{
                color: #003366;
            }}
            p {{
                margin-bottom: 20px;
            }}
            .cta-button {{
                display: inline-block;
                background-color: #003366;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <p>Dear {name},</p> <p>To activate your account, we kindly request you to 
        verify your email address.</p> <p>To proceed with the verification process, please click the button 
        below:</p> <a class="cta-button" href="{url_for('verify_email', token=token, _external=True)}">Verify Email 
        Address</a>
        <p>If you did not initiate this registration or have any concerns, please disregard this email.</p>
        <p>Thank you for choosing our platform.</p>
        <p>Best regards,<br>Team SPC</p>
    </body>
    </html>
    '''

    message = Message(subject, recipients=[email], html=body)
    mail.send(message)


def send_deployment_email(name, email):
    subject = 'Your VM has been Created'
    body = f'''
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.5;
            }}

            h1 {{
                color: #003366;
            }}

            p {{
                margin-bottom: 20px;
            }}

            .container {{
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                border: 1px solid #ccc;
                border-radius: 8px;
                background-color: #f9f9f9;
            }}

            .header {{
                background-color: #003366;
                color: #fff;
                padding: 10px;
                text-align: center;
            }}

            .content {{
                padding: 20px;
            }}

            .footer {{
                background-color: #003366;
                color: #fff;
                padding: 10px;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1> Notification</h1>
            </div>
            <div class="content">
                <p>Dear {name},</p>
                <p>Your VM is now ready for use.</p>
                <p>Thank you for choosing our services.</p>
            </div>
            <div class="footer">
                <p>Team SPC</p>
            </div>
        </div>
    </body>
    </html>
    '''

    message = Message(subject, recipients=[email], html=body)
    mail.send(message)


def admin_required(view_func):
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            return redirect('/dashboard')
        return view_func(*args, **kwargs)

    return wrapper


@app.route('/admin')
@login_required
@admin_required
def admin():
    connection = create_connection()
    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM request_vm where status='unapproved'"  # Replace with your table name
            cursor.execute(sql)
            data = cursor.fetchall()
    finally:
        connection.close()
    return render_template('data.html', data=data)  # Pass the data to the template


@app.route('/list-users')
def list_users():
    request = {
        'command': 'listUsers',
        'response': 'json',
        'apikey': api_key
    }
    res = send_api_request(request)

    # Check if response is valid
    print(res)

    # Render HTML template
    return res


@app.route('/')
def index():
    logged_in = current_user.is_authenticated
    return render_template('index1.html', logged_in=logged_in)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/services')
def services():
    return render_template('services.html')


@app.route('/faq')
def faq():
    return render_template('faq.html')


@app.route('/vmachine')
def vmachine():
    return render_template('vmachine.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    user_data = current_user

    return render_template('profile.html', user_data=user_data)


@app.route('/dashboard')
@login_required
def user_dashboard():
    # use this to fetch vm details from database for the logged-in user
    us = current_user
    r_no = us.regno
    connection = create_connection()
    try:
        with connection.cursor() as cursor:
            sql = "SELECT t1.*, t2.* FROM vm t1 JOIN request_vm t2 ON t1.reg_no = t2.reg_no WHERE t1.reg_no = %s"
            cursor.execute(sql, r_no)
            data = cursor.fetchall()
            print(data)

    finally:
        connection.close()

    if us:
        # Check the 'status' field in the data tuple
        if data and data[0].get('status') == 'Approved':
            # Check if the email has been sent for this deployment
            if 'email_sent' not in session:
                # Send the email notification here
                name = current_user.name
                send_deployment_email(name, current_user.email)
                # Set the email_sent flag in the session to prevent future emails
                session['email_sent'] = True

        return render_template('dashboard.html', data=data)

    return render_template('404.html')


def check_if_user_has_vm(regno):
    connection = create_connection()
    try:
        with connection.cursor() as cursor:
            sql = "SELECT COUNT(*) FROM request_vm WHERE reg_no = %s"
            cursor.execute(sql, (regno,))
            result = cursor.fetchone()
            print(result)
            if result:
                return result

    finally:
        connection.close()


@app.route('/vm', methods=['POST', 'GET'])
@login_required
def vm_request():
    us = current_user
    has_vm = check_if_user_has_vm(us.regno)
    if reqf.method == 'GET':
        if isinstance(has_vm, dict) and 'COUNT(*)' in has_vm:
            if has_vm['COUNT(*)'] == 0:
                # Function to check if the user has a VM, returns True or False
                return render_template('request.html', us=us)
            else:
                return render_template('404.html')

    if reqf.method == 'POST':
        vm_name = reqf.form.get('vmname')
        os_name = reqf.form.get('os')
        vm_type = reqf.form.get('vmtype')
        disk_size = reqf.form.get('disksize')
        dept = us.dept
        rno = us.regno
        # dept = request.form.get('department', '')
        # You can choose to return an error response or redirect the user to a specific page.
        vm_name = re.sub(' +', '-', vm_name)

        print(vm_name)
        print(vm_type)
        print(os_name)
        print(dept)
        print(rno)

        connection = create_connection()
        try:
            with connection.cursor() as cursor:
                sql = "INSERT INTO request_vm( reg_no, display_name, vm_type, os, department, disk_size) VALUES " \
                      "(%s,%s,%s,%s,%s,%s)"
                cursor.execute(sql, (rno, vm_name, vm_type, os_name, dept, disk_size))
                connection.commit()
                return redirect('/dashboard')
        finally:
            connection.close()

    return render_template('request.html', us=us)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect logged-in users to a different page
        return redirect(url_for('user_dashboard'))
    connection = create_connection()
    if reqf.method == 'POST':
        regno = reqf.form['regno']
        password = reqf.form['password']

        with connection.cursor() as cursor:
            sql = "SELECT * FROM user WHERE reg_no = %s"
            cursor.execute(sql, (regno,))
            user = cursor.fetchone()
            if user and user['password'] == password:
                if user['status'] == 'verified':  # Check if the user status is verified
                    login_user(User(user))
                    if user['is_admin']:
                        return redirect('/admin')
                    return redirect(url_for('user_dashboard'))
                else:
                    return render_template('login.html', error='Your account is not verified.')

        return render_template('login.html', error='Invalid registration number or password')

    return render_template('login.html')


@app.route('/deploy-vm', methods=['GET', 'POST'])
def deploy_vm():
    global os_id

    vm_name = reqf.form.get('vm_name')
    print(vm_name)
    reg_no = reqf.form.get('regno')
    os_name = reqf.form.get('os')
    disk_size = reqf.form.get('disk_size')
    print(disk_size)
    os_id = {
        'ubuntu': '29ad40ad-ca55-4897-8943-eaa881506fe7',
        'windows': '94e94524-0ae2-4b22-b1e9-271417057e16',
        'debian': '8f35ec03-fb6d-413b-932f-8ec5b4edf546',  # Replace 'your_debian_id_here' with the actual ID
    }.get(os_name, '966fee32-43e6-42ba-9f01-0db2875aeba5')
    print(os_name)
    print(os_id)
    request = {
        'command': 'deployVirtualMachine',
        'response': 'json',
        'apikey': api_key,
        'serviceofferingid': '38f991e6-0519-4d53-8f1b-2d3fb057332a',
        'templateid': os_id,
        'zoneid': 'ebeae8ad-582c-4ea7-9012-52238084af64',
        'name': vm_name,
        'networkids': '886043f1-4289-4897-8e0e-0881b8182ec8',
        'rootdisksize': '50',
        'keypair': 'access'

    }
    res = send_api_request(request)

    # Check if response is valid
    print(res)
    try:
        job_id = json.loads(res)['deployvirtualmachineresponse']['jobid']
        session['jobid'] = job_id
        session['reg_num'] = reg_no

    except KeyError:
        return 'Invalid response from API'

    return redirect('/details')


# return f"VM deployment in progress. Job ID: {job_id}"

@app.route('/start_vm/<vm_id>')
@login_required
def start_vm(vm_id):
    try:
        request = {
            'command': 'startVirtualMachine',
            'id': vm_id,
            'apikey': api_key
        }

        res = send_api_request(request)
        print(res)

        return "Successfully started the machine"
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/destroy_vm/<vm_id>')
@login_required
def destroy_vm(vm_id):
    try:

        # Prepare the API request to destroy the VM with expunge parameter
        request = {
            'command': 'destroyVirtualMachine',
            'id': vm_id,
            'expunge': 'true',  # Set the expunge parameter to 'true' for permanent destruction
            'apikey': api_key
        }
        res = send_api_request(request)
        print(res)

        return "Successfully destroyed the virtual machine"

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stop_vm/<vm_id>')
@login_required
def stop_vm(vm_id):
    try:
        request = {
            'command': 'stopVirtualMachine',
            'id': vm_id,
            'apikey': api_key
        }

        res = send_api_request(request)
        print(res)

        return "Successfully stopped the machine"
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/details', methods=['GET'])
@login_required
def query_job_completion():
    time.sleep(7)
    j_id = session.get('jobid')
    print("Retrieved Job ID from session:", j_id)
    request = {
        'command': 'queryAsyncJobResult',
        'response': 'json',
        'apikey': api_key,
        'jobid': j_id
    }
    res = send_api_request(request)
    print(res)
    # Check if response is valid
    try:
        job_result = json.loads(res)['queryasyncjobresultresponse']['jobresult']
        print(job_result)
        if 'virtualmachine' in job_result:
            vm_id = job_result['virtualmachine']['id']
            ip_address = job_result['virtualmachine']['nic'][0]['ipaddress']
            connection = create_connection()
            with connection.cursor() as cursor:
                sql = "INSERT INTO vm (vm_id, ip_address, reg_no) VALUES (%s, %s, %s)"
                reg_no = session.get('reg_num')
                values = (vm_id, ip_address, reg_no)
                try:
                    # Execute the SQL query with the provided values
                    cursor.execute(sql, values)
                    # Commit the changes to the database
                    connection.commit()

                    sql = "UPDATE request_vm SET status = 'Approved' WHERE reg_no = %s"
                    cursor.execute(sql, reg_no)
                    connection.commit()
                except pymysql.Error as e:
                    # Handle the exception
                    print(f"Error occurred: {e}")

            return redirect('/admin')

        else:
            return 'deployment in progress'
    except KeyError:
        return redirect('/details')


@app.route('/query_vm_state/<vm_id>')
def query_vm_state(vm_id):
    try:
        # Prepare the API request to query the VM state
        request = {
            'command': 'listVirtualMachines',
            'id': vm_id,
            'apikey': api_key
        }

        res = send_api_request(request)
        print(res)

        # Parse the response and extract the VM state
        root = ET.fromstring(res)
        vm_elements = root.findall('.//virtualmachine')
        if len(vm_elements) > 0:
            vm_state = vm_elements[0].find('state').text
            return vm_state
        else:
            return jsonify({'error': 'Failed to retrieve VM state.'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/sshkeygen')
@login_required
def create_ssh_keypair():
    try:
        # Prepare the API request to query the VM state
        request = {
            'command': 'createSSHKeyPair',
            'name': 'test-key',
            'apikey': api_key

        }

        res = send_api_request(request)
        print(res)
        return res
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reset_vm/<vm_id>')
@login_required
def reset_virtual_machine(vm_id):
    try:
        request = {
            'command': 'restoreVirtualMachine',
            'virtualmachineid': vm_id,
            'apikey': api_key
        }
        res = send_api_request(request)
        print(res)
        return "Successfully restored the virtual machine."

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Vlabs -deployment API
@app.route('/api/deploy-vm', methods=['POST'])
def api_deploy_vm():
    global os_id
    os_name = reqf.form.get('name')  # Change from reqf.form to request.form
    print(os_name)
    os_id = {
        'nmap': '5fbb05fd-43b3-4f50-b483-b0564d15f77a',
        'sql': '94e94524-0ae2-4b22-b1e9-271417057e16',
        'xss': '8f35ec03-fb6d-413b-932f-8ec5b4edf546',  # Replace 'your_debian_id_here' with the actual ID
    }.get(os_name, '966fee32-43e6-42ba-9f01-0db2875aeba5')

    # Generate a random VM name using uuid
    vm_name = 'vm_' + str(uuid.uuid4())[:8]

    request_data = {
        'command': 'deployVirtualMachine',
        'response': 'json',
        'apikey': api_key,
        'serviceofferingid': '38f991e6-0519-4d53-8f1b-2d3fb057332a',
        'templateid': os_id,
        'zoneid': 'ebeae8ad-582c-4ea7-9012-52238084af64',
        'name': vm_name,
        'networkids': '886043f1-4289-4897-8e0e-0881b8182ec8',
        'diskofferingid': 'd753d61a-7dfa-4ac7-9df4-105538929d46'
    }

    res = send_api_request(request_data)

    # Check if response is valid
    try:
        job_id = json.loads(res)['deployvirtualmachineresponse']['jobid']
        session['jobid'] = job_id
    except KeyError:
        return jsonify({'error': 'Invalid response from API'})

    # Query for the IP address using the job_id
    ip_request_data = {
        'command': 'queryAsyncJobResult',
        'response': 'json',
        'apikey': api_key,
        'jobid': job_id,
    }

    ip_res = send_api_request(ip_request_data)

    # Extract the IP address from the response
    try:
        ip_address = json.loads(ip_res)['queryasyncjobresultresponse']['jobresult']['virtualmachine']['nic'][0][
            'ipaddress']
    except KeyError:
        return jsonify({'error': 'Unable to retrieve IP address'})

    return jsonify({'success': True, 'message': 'VM deployment initiated successfully', 'vm_name': vm_name,
                    'ip_address': ip_address})


# @app.route('/restart')
# def restart_network():
#     request = {
#         'command': 'restartNetwork',
#         'id': 'ed726ecd-6be3-4217-b7dd-24b79e9f4ab3',
#         'apikey': api_key,
#         'makeredundant': 'true'
#     }
#     res = send_api_request(request)
#     return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
