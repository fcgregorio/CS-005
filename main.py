from flask import Flask, render_template, request, redirect, url_for, flash
from forms import LoginForm, MessageForm, RegistrationForm, PasswordChangeForm
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Message
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta
import copy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = b'\x0f\xd6T\x85\xc0\xb9\xf4\xaex\xbbh;\x80\xb8NX'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated and \
       current_user.is_password_expired():
        return redirect(url_for('password_change'))

    form = MessageForm(request.form)

    if current_user.is_authenticated and request.method == 'POST' and form.validate():
        message = Message(form.content.data)
        current_user.messages.append(message)
        db.session.commit()
        return redirect(url_for('index'))

    messages = Message.query.order_by(Message.created_at.desc()).all()
    return render_template('index.html', form=form, messages=messages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.first_name.data, form.last_name.data, form.username.data, form.email.data, form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login', username=user.username))
    return render_template('register.html', form=form)
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'GET':
        username = request.args.get('username')
        form = LoginForm(username=username)        
    else:
        form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and \
           len(user.login_attempt_history) >= 3 and \
           user.login_attempt_history[0] + timedelta(minutes=5) > datetime.now():
            flash('Too many login attempts. Try again later.', 'danger')
        elif user and \
             user.verify_password(form.password.data):
            user.login_attempt_history = []
            db.session.commit()

            login_user(user, remember=True)

            return redirect(url_for('index'))
        elif user:
            login_attempt_history = copy.deepcopy(user.login_attempt_history)
            login_attempt_history.insert(0, datetime.now())
            user.login_attempt_history = login_attempt_history[:4]
            db.session.commit()

            flash('Invalid credentials.', 'danger')
        else:
            flash('Invalid credentials.', 'danger')
    else:
        flash('Invalid credentials.', 'danger')

    return render_template('login.html', form=form)


@app.route('/password-change', methods=['GET', 'POST'])
@login_required
def password_change():
    form = PasswordChangeForm(request.form)
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.username.data = current_user.username
    
    if request.method == 'POST' and form.validate():
        if current_user.verify_password(form.password.data):

            if any(check_password_hash(password, form.new_password.data) for password in current_user.password_history) or \
               check_password_hash(current_user.password, form.new_password.data):
                flash('Password must not be the same with any of the 6 previous passwords.', 'danger')
            else:
                password_history = copy.deepcopy(current_user.password_history)
                password_history.insert(0, current_user.password)
                current_user.password_history = password_history[:6]
                current_user.password = generate_password_hash(form.new_password.data)
                current_user.password_updated_at = datetime.now()
                db.session.commit()

                flash('Password changed.', 'success')
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('password_change.html', form=form)



@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
