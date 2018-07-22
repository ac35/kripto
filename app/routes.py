from datetime import datetime
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm
from app.models import User
from app.email import send_password_reset_email, send_confirmation_link_email
from app.decorators import check_confirmed


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@app.route('/')
@app.route('/index')
# @login_required
def index():
    return render_template('index.html', title='Home')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            send_confirmation_link_email(user)
            flash('A confirmation email has been sent via email.')
            return redirect(url_for('login'))   #  cocok kah ke login?
    return render_template('register.html', title='Register', form=form)


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
        if user.confirmed is False:
            return redirect(url_for('unconfirmed'))
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    user = User.verify_confirm_email_token(token)
    if not user:
        return redirect(url_for('index'))
    user.confirmed = True
    db.session.add(user)
    db.session.commit()
    flash('You have confirmed your account.')
    return redirect(url_for('login'))


@app.route('/user/<username>')
@login_required
@check_confirmed
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
@check_confirmed
def encrypt():
    if not current_user.confirmed:
        pass
    return render_template('encrypt.html', title='Encrypt')


@app.route('/about')
def about():
    user = User.query.filter_by(email='alvinchandra783@gmail.com').first()
    return render_template('about.html', title='About', user=user)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect(url_for('index'))
    return render_template('unconfirmed.html')


@app.route('/resend_confirmation')
@login_required
def resend_confirmation():
    if current_user.confirmed:
        return redirect(url_for('index'))
    send_confirmation_link_email(current_user)
    flash('A new confirmation email has been sent.')
    return redirect(url_for('unconfirmed'))
