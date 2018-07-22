from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')


class EncryptForm(FlaskForm):
    file = FileField('File to encrypt', validators=[FileRequired()])
    base_key = PasswordField("Key", validators=[DataRequired()])
    recipient = SelectField("Recipient", coerce=int)
    comment = TextAreaField("Comment", validators=[DataRequired()])
    password = PasswordField("Your password", validators=[Length(min=0, max=140)])
    submit = SubmitField('Encrypt')

    def __init__(self, *args, **kwargs):
        super(EncryptForm, self).__init__(*args, **kwargs)
        # self.sender = user
        # tangani recipient
        self.recipient.choices = [(current_user.id, current_user.username)]
        self.recipient.choices += [(u.id, u.username) for u in User.query.filter(User.id != current_user.id).all()]
        # self.recipient.choices.insert(0, '---Select User---')

    def validate_password(self, password):
        if current_user.check_password(password.data) is False:
            raise ValidationError('Invalid password.')
