from flask import Flask, render_template, request, redirect, url_for, flash, abort
from forms import LoginForm, MessageForm, RegistrationForm, PasswordChangeForm, UpdateUserForm, FollowUnfollowForm
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


@app.route('/users/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()

    if user is None:
        abort(404, description="User not found")

    messages = Message.query.filter_by(user=user).order_by(Message.created_at.desc()).all()
    return render_template('user.html', user=user, messages=messages)


@app.route('/users/<username>/edit', methods=['GET', 'POST'])
def user_edit(username):
    user = User.query.filter_by(username=username).first()

    if user is None:
        abort(404, description="User not found")

    if not current_user.is_authenticated:
        abort(403)

    if user.id != current_user.id:
        abort(403)

    if request.method == 'GET':
        form = UpdateUserForm(first_name=user.first_name, last_name=user.last_name, username=user.username, email=user.email)        
    elif request.method == 'POST':
        form = UpdateUserForm(request.form)

        if form.validate():
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            user.username = form.username.data
            user.email = form.email.data
            db.session.commit()
            return redirect(url_for('user', username=user.username))
    return render_template('user_edit.html', form=form)


@app.route('/message/<id>/edit', methods=['GET', 'POST'])
def message_edit(id):
    message = Message.query.get(id)

    if message is None:
        abort(404, description="Message not found")

    if not current_user.is_authenticated:
        abort(403)

    if message.user.id != current_user.id:
        abort(403)
    
    if request.method == 'GET':
        form = MessageForm(content=message.content)        
    elif request.method == 'POST':
        form = MessageForm(request.form)

        if form.validate():
            message.content = form.content.data
            db.session.commit()
            return redirect(url_for('message_edit', id=id))

    return render_template('message_edit.html', form=form, message=message)


@app.route('/message/<id>/delete', methods=['POST'])
def message_delete(id):
    message = Message.query.get(id)

    if message is None:
        abort(404, description="Message not found")

    if not current_user.is_authenticated:
        abort(403)

    if message.user.id != current_user.id:
        abort(403)

    db.session.delete(message)
    db.session.commit()
    return redirect(url_for('index'))


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
    elif request.method == 'POST':
        form = LoginForm(request.form)

        if form.validate():
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
                form.new_password.errors.append('Password must not be the same with any of the 6 previous passwords.')
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


@app.route('/follow', methods=['POST'])
@login_required
def follow():
    form = FollowUnfollowForm(request.form)
    
    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()

        follow = Follow(subject_user_id=current_user.id, object_user_id=user.id)
        db.session.commit()
        return None, 201


@app.route('/unfollow', methods=['POST'])
@login_required
def unfollow():
    form = FollowUnfollowForm(request.form)
    
    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        follow = Follow.query.filter_by(subject_user_id=current_user.id, object_user_id=user.id).first()
        
        db.session.delete(follow)
        db.session.commit()
        return None, 200


@app.route('/followers', methods=['GET'])
@login_required
def followers():
    followers = Follow.query.filter_by(object_user_id=current_user.id).all()

    return followers, 200


@app.route('/following', methods=['GET'])
@login_required
def following():
    following = Follow.query.filter_by(subject_user_id=current_user.id).all()

    return following, 200


if __name__ == '__main__':
    app.run(debug=True)