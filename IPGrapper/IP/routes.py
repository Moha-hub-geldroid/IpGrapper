from flask import render_template,url_for,flash,redirect,request,abort
from IP.forms import RegistrationForm,LoginForm,Dashboard,RequestReset,ResetPassword
from IP import app,db,mail
from IP.models import User,Victims
from werkzeug.utils import secure_filename
from flask_login import login_user,logout_user,current_user,login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from werkzeug.utils import secure_filename
import os
from user_agents import parse
import requests
import xml.etree.ElementTree as ET



def send_reset_message(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',sender="gashehteam@gmail.com",recipients=[user.email],
    body=f'''Hi Mr/Mrs {user.first_name},
The link below will let you reset your password : {url_for('password_reset',token=token,_external=True)}

This link is valid for 15 minutes .

if you did not request to change your password , just ignore this message .''')
    mail.send(msg)

def send_confirm_message(user):
    token = user.confirmation_token
    msg = Message('Email Confirmation',sender="gashehteam@gmail.com",recipients=[user.email],
    body=f'''Hi Mr/Mrs {user.first_name},
Pleasw confirm your account from this link : {url_for('confirm_email',token=token,_external=True)}
''')
    mail.send(msg)

@app.route("/")
@app.route("/home",methods=["GET"])
def home():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    return render_template("home.html",title="Home Page")

@app.route("/register", methods=["GET", "POST"])
def register():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()

    if form.validate_on_submit():
        current_password = form.password.data
        hashed_password = generate_password_hash(current_password, method='pbkdf2:sha256')
        def generate_random_token(length=16):
            random_bytes = os.urandom(length)
            random_token = ''.join('{:02x}'.format(byte) for byte in random_bytes)
            return random_token
        confirmation_token = generate_random_token(16)
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data,email=form.email.data, password=hashed_password, confirmation_token=confirmation_token,confirmed=False)

        with app.app_context():
            db.session.add(user)
            db.session.commit()
            user = User.query.filter_by(email=form.email.data).first()
            send_confirm_message(user)
            flash('Account created successfully. Check your email for confirmation instructions.', 'success')
            try:
                return redirect(url_for('logout'))  
            except:
                return redirect(url_for('login'))  
        
    return render_template("register.html", title="Register", form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            if user.confirmed:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Account is not confirmed yet. Please check your email inbox to confirm it first.', 'info')
        else:
            flash('Email or password is incorrect. Double-check your credentials and try again!', 'danger')
    
    return render_template("login.html", title="Login", form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    user = User.query.filter_by(confirmation_token=token).first_or_404()

    if user.confirmed:
        flash('Account already confirmed. Please log in.', 'info')
    else:
        user.confirmed = True
        db.session.commit()
        flash('Account confirmed! You can now log in.', 'success')
        return redirect(url_for('login'))

    return redirect(url_for('home'))

@app.route("/logout")
@login_required
def logout():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    logout_user()
    return redirect(url_for('login'))
    

@app.route("/dashboard",methods=["GET","POST"])
@login_required
def dashboard():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    form = Dashboard()
    if form.validate_on_submit():
        with app.app_context():
            current_user.username = form.username.data
            current_user.email = form.email.data
            db.session.commit()
            flash(f'Your data is updated successfully!',"success")
        return redirect(url_for("dashboard"))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email 
    return render_template("dashboard.html",title="Dashboard",form=form)
    
    return render_template("dashboard.html",title="Dashboard")

@app.route("/delete_account",methods=["POST"])
@login_required
def delete_account():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    if current_user.is_authenticated:
        with app.app_context():
            db.session.delete(current_user)
            db.session.commit()
        flash(f"Your account was deleted successfully!","success")
        return redirect(url_for("register"))
    else:
        return redirect(url_for("login"))
    return redirect(url_for("home"))


@app.route('/reset_password',methods=['GET','POST'])
def request_reset():
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestReset()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_message(user)
        flash('check your email for reset link, please!','info')
        return redirect(url_for('home'))
    return render_template('reset_request.html',title="Request password reset",form=form)

@app.route('/reset_password/<token>',methods=['GET','POST'])
def password_reset(token):
    victims= Victims.query.all()
    for victim in victims:
        if request.remote_addr == victim.visitor_ip:
            return redirect('error403')
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.check_token_validate(token)
    if not user:
        flash('This token is invalid or expired!','warning')
        return redirect(url_for('request_reset'))
    
    form = ResetPassword()
    if form.validate_on_submit():
        new_password = form.password.data
        hashed_password = generate_password_hash(new_password,method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been changed successfully!','success')
        return redirect(url_for('login'))
    return render_template('reset_password.html',title="Reset password",form=form)

@app.errorhandler(404)
def error404(error):
    return render_template('404.html',title="404 - Not Found"),404
    
@app.errorhandler(403)
def error403(error):
    return render_template('403.html',title="403 - Forbidden"),403

@app.errorhandler(500)
def error500(error):
    return render_template('500.html',title="500 - server error"),500

@app.route('/<username>')
def landpage(username):
    try:
        user = User.query.filter_by(username=username).first()
        def get_user_ip():
            if 'X-Forwarded-For' in request.headers:
                ips = request.headers['X-Forwarded-For'].split(',')
                return ips[0].strip() 
            return request.remote_addr
        victim_ip = get_user_ip()
        def get_os_info():
            try:
                return request.user_agent.platform
            except:
                return "Not available"
        os_info = get_os_info()
        if os_info is None:
            os_info = "Unknown"
        
        def get_device_name():
            try:
                user_agent_string = request.user_agent.string
                user_agent = parse(user_agent_string)
                device_name = user_agent.device.family
                return device_name
            except:
                return "Not available"
        device_name = get_device_name()
        if device_name is None:
            device_name = "Unknown"
        def get_ip_details(victim_ip):
            url = f'http://www.geoplugin.net/xml.gp?ip={victim_ip}'
            
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    # Parse XML response
                    root = ET.fromstring(response.content)
                    return root
                else:
                    return None
            except Exception as e:
                print(e)
                return None
        
        ip_details = get_ip_details(victim_ip)
        if ip_details is not None:
            country = ip_details.findtext('.//geoplugin_countryName')
            city = ip_details.findtext('.//geoplugin_city')
        else:
            country = 'Unknown'
            city = 'Unknown'
        new_victim = Victims(visitor_ip=victim_ip,user_id=user.id,device_name=device_name,os_info=os_info,country=country,city=city)
        with app.app_context():
            db.session.add(new_victim)
            db.session.commit()
    except Exception as s:
        print(s)
    return render_template("403.html",title="Forbidden")


        
@app.route('/victims',methods=['GET','POST'])
@login_required
def victims():
    #victims= Victims.query.all()
#    for victim in victims:
#        if request.remote_addr == victim.visitor_ip:
#            return redirect('error403')
    user_id = current_user.id
    victims = Victims.query.filter_by(user_id=user_id).all()
    return render_template("victims.html",title="Victims Page",victims=victims)
    
@app.route('/delete_victim',methods=['GET','POST'])
@login_required
def delete_victim():
    #victims= Victims.query.all()
#    for victim in victims:
#        if request.remote_addr == victim.visitor_ip:
#            return redirect('error403')
    victim_ip = request.args.get('victim_ip')
    user_id = request.args.get('user_id')
    try:
        
        with app.app_context():
            victim = Victims.query.filter_by(visitor_ip=victim_ip,user_id=user_id).first()
            db.session.delete(victim)
            db.session.commit()
            flash('victim details was deleted successfully!','success')
    except Exception as e:
        abort(500)
    return redirect(url_for('victims'))
