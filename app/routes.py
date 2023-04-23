from flask import render_template, flash, redirect, url_for, request, Response
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from sqlalchemy import exists

from datetime import datetime

from app.forms import LoginForm, RegistrationForm, EditAboutMeForm
from app.models import User, Post
from . import app, db


@app.route('/')
@login_required
def index():
    posts = Post.query.all()
    resp = Response(render_template('index.html', title='Base', posts=posts))
    resp.headers['Flag'] = 'SgffCTF{0h_my_g0d}'
    return resp


@app.route('/secret')
def secret():
    cookie = request.cookies.get('i_want_flag')
    if cookie == 'yes':
        return 'Yeah! Your flag is Sgff{c00kie5_ar3_v3ry_ta5t3}'
    else:
        return 'No! You should set cookie i_want_flag=yes'

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('profile.html', user=user, posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            return redirect(url_for('index'))
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        email_exists = db.session.query(
            exists().where(User.email == user.email)
        ).scalar()
        username_exists = db.session.query(
            exists().where(User.username == user.username)
        ).scalar()
        if email_exists or username_exists:
            flash('Email or password already exists.')
        else:
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('New user registered')
            return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


"""@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    form = EditAboutMeForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes has been saved!')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form)"""


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
