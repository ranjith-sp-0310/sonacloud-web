import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib
import urllib.request
from urllib3 import request
import urllib.parse
from flask import Flask, render_template, request, url_for, send_from_directory, json, session, jsonify
from flask import request as reqf
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.utils import redirect
import pymysql
from flask_mail import Mail, Message
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = 'dGhpc2lzbXlhcHBzZWNyZWF0a2V5'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ranjithsp199@gmail.com'
app.config['MAIL_PASSWORD'] = 'rrwgxxhrcpeffuxc'
app.config['MAIL_DEFAULT_SENDER'] = 'ranjithsp199@gmail.com'

mail = Mail(app)

host = 'localhost'  # Replace with your MySQL host
user = 'root'  # Replace with your MySQL username
password = ''  # Replace with your MySQL password
database = 'users'  # Replace with your MySQL database name
baseurl = 'http://172.16.23.5:8080/client/api?'
secretkey = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'


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


@app.route('/admin/approvedvm')
@login_required
def approved_vm():
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
    if request.method == 'POST':
        # Get the user data from the form
        name = request.form['name']
        email = request.form['email']
        regno = request.form['regno']
        dept = request.form['department']
        user_password = request.form['password']
        print(regno)
        # Generate a verification token
        token = generate_verification_token()
        # Send the verification email
        send_verification_email(name, email, token)
        # Save the user details and token to the database
        save_user_to_database(name, email, token, regno, user_password, dept)
        # Redirect the user to a verification page or show a success message
        return render_template('verify.html')

    return render_template('register.html')


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
    subject = 'Email Verification'
    body = f'''
    Hi {name},

    Please verify your email address by clicking the following link:
    {url_for('verify_email', token=token, _external=True)}

    If you did not register on our website, please ignore this email.

    Regards,
    Your Website Team
    '''

    message = Message(subject, recipients=[email], body=body)
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
    baseurl = 'http://172.16.23.5:8080/client/api?'
    request = {
        'command': 'listUsers',
        'response': 'json',
        'apikey': 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g',
    }
    request_str = urllib.parse.urlencode(request)

    sig_str = '&'.join(['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
                        sorted(request.keys())])
    sig = base64.b64encode(hmac.new(secretkey.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
        'utf-8')
    req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

    with urllib.request.urlopen(req) as response:
        res = response.read().decode('utf-8')

    # Check if response is valid
    print(res)
    try:
        data = json.loads(res)['listusersresponse']['user']
    except KeyError:
        return 'Invalid response from API'

    # Generate HTML table
    table = '<table><tr><th>Username</th><th>First Name</th><th>Last Name</th></tr>'
    for user in data:
        table += f'<tr><td>{user["username"]}</td><td>{user["firstname"]}</td><td>{user["lastname"]}</td></tr>'
    table += '</table>'

    # Render HTML template
    return render_template('list_users.html', table=table)


@app.route('/')
def index():
    logged_in = current_user.is_authenticated
    return render_template('home.html', logged_in=logged_in)


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
    if request.method == 'GET':
        if isinstance(has_vm, dict) and 'COUNT(*)' in has_vm:
            if has_vm['COUNT(*)'] == 0:
                # Function to check if the user has a VM, returns True or False
                return render_template('request.html', us=us)
            else:
                return render_template('404.html')

    if request.method == 'POST':
        vm_name = request.form.get('vmname')
        os_name = request.form.get('os')
        vm_type = request.form.get('vmtype')
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
                sql = "INSERT INTO request_vm( reg_no, display_name, vm_type, os, department) VALUES " \
                      "(%s,%s,%s,%s,%s)"
                cursor.execute(sql, (rno, vm_name, vm_type, os_name, dept))
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
    if request.method == 'POST':
        regno = request.form['regno']
        password = request.form['password']

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
    baseurl = 'http://172.16.23.5:8080/client/api?'

    vm_name = reqf.form.get('vm_name')
    print(vm_name)
    reg_no = reqf.form.get('regno')
    # if reqf.form.get('os') == 'ubuntu':
    #     print(reqf.form.get('os'))
    #     os_id = '43495c56-0ba7-43bd-8c93-446dd275e136'
    # else:
    #     print(reqf.form.get('os'))
    #     os_id = '5ea4420d-d853-11ed-8930-0068ebc8ff53'
    os_id = '028c1441-acff-45f8-b8f9-0bf2e7da8387'
    request = {
        'command': 'deployVirtualMachine',
        'response': 'json',
        'apikey': 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g',
        'serviceofferingid': 'fe8df1d3-3cea-421a-a4fe-4d9d2e366fce',
        'templateid': os_id,
        'zoneid': '377bdc02-beea-471e-8bdc-b2becb2e0502',
        'name': vm_name,
        'networkids': '95d97ef6-fd9d-49b9-b0a4-6dd8df776962',
        'rootdisksize': '20',
        'keypair': 'Ubuntu'

    }
    request_str = urllib.parse.urlencode(request)

    sig_str = '&'.join(['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
                        sorted(request.keys())])
    sig = base64.b64encode(hmac.new(secretkey.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
        'utf-8')
    req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

    with urllib.request.urlopen(req) as response:
        res = response.read().decode('utf-8')

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
def start_vm(vm_id):
    try:
        secret_key = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'
        api_key = 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g'

        request = {
            'command': 'startVirtualMachine',
            'id': vm_id,
            'apikey': api_key
        }

        request_str = urllib.parse.urlencode(request)

        sig_str = '&'.join(
            ['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
             sorted(request.keys())])
        sig = base64.b64encode(
            hmac.new(secret_key.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
            'utf-8')
        req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

        with urllib.request.urlopen(req) as response:
            res = response.read().decode('utf-8')
            print(res)

        return "Successfully started the machine"
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/destroy_vm/<vm_id>')
def destroy_vm(vm_id):
    try:
        secret_key = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'
        api_key = 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g'

        # Prepare the API request to destroy the VM with expunge parameter
        request = {
            'command': 'destroyVirtualMachine',
            'id': vm_id,
            'expunge': 'true',  # Set the expunge parameter to 'true' for permanent destruction
            'apikey': api_key
        }
        request_str = urllib.parse.urlencode(request)

        sig_str = '&'.join(
            ['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
             sorted(request.keys())])
        sig = base64.b64encode(
            hmac.new(secret_key.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
            'utf-8')
        req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

        with urllib.request.urlopen(req) as response:
            res = response.read().decode('utf-8')
            print(res)

        return "Successfully destroyed the virtual machine"

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stop_vm/<vm_id>')
def stop_vm(vm_id):
    try:
        secret_key = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'
        api_key = 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g'

        request = {
            'command': 'stopVirtualMachine',
            'id': vm_id,
            'apikey': api_key
        }

        request_str = urllib.parse.urlencode(request)

        sig_str = '&'.join(
            ['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
             sorted(request.keys())])
        sig = base64.b64encode(
            hmac.new(secret_key.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
            'utf-8')
        req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

        with urllib.request.urlopen(req) as response:
            res = response.read().decode('utf-8')
            print(res)

        return "Successfully stopped the machine"
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/details', methods=['GET'])
def query_job_completion():
    time.sleep(7)
    secret_key = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'
    # job_id = '8c9d174e-4c1a-45f4-bf31-e9e57086b50b'
    j_id = session.get('jobid')
    print("Retrieved Job ID from session:", j_id)

    print(j_id)
    request = {
        'command': 'queryAsyncJobResult',
        'response': 'json',
        'apikey': 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g',
        'jobid': j_id
    }
    request_str = urllib.parse.urlencode(request)

    sig_str = '&'.join(['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
                        sorted(request.keys())])
    sig = base64.b64encode(hmac.new(secret_key.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
        'utf-8')
    req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)

    with urllib.request.urlopen(req) as response:
        res = response.read().decode('utf-8')
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
        secret_key = 'B6ai5zG3RslVtiV1rZEHrqUOJfqBHt_Ll7I969OH8-NYouO3auWTB6eA-Bz9wIZ0bqvZQL7kiCg9r43kbcssiw'
        api_key = 'Usqb-YiWi0eukSu5ksIg8cy-5CayR0ohP6HR1B7Snf7AkaKKSkhyqhgRESsXgIg7nQk0_pWtEsOx4ULOIO0d3g'

        # Prepare the API request to query the VM state
        request = {
            'command': 'listVirtualMachines',
            'id': vm_id,
            'apikey': api_key
        }

        request_str = urllib.parse.urlencode(request)

        sig_str = '&'.join(
            ['='.join([k.lower(), urllib.parse.quote_plus(request[k].lower().replace('+', '%20'))]) for k in
             sorted(request.keys())])
        sig = base64.b64encode(
            hmac.new(secret_key.encode('utf-8'), sig_str.encode('utf-8'), hashlib.sha1).digest()).decode(
            'utf-8')
        req = baseurl + request_str + '&signature=' + urllib.parse.quote_plus(sig)
        # Send the API request and get the response
        with urllib.request.urlopen(req) as response:
            res = response.read().decode('utf-8')
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
