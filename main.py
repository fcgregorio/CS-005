from flask import Flask, render_template, request, redirect, url_for, flash
from forms import LoginForm, MessageForm, RegistrationForm
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Message
from flask_login import LoginManager, login_user, logout_user, current_user, login_required


app = Flask(__name__)
app.secret_key = b'\x0f\xd6T\x85\xc0\xb9\xf4\xaex\xbbh;\x80\xb8NX'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/', methods=['GET', 'POST'])
def index():
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
        
        if user and user.verify_password(form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))