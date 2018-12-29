import app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError



class RegistrationFormDonator(FlaskForm):

    company_name = StringField('Company Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    vat = StringField('VAT (ex. P.IVA)',
                           validators=[DataRequired(), Length(min=0, max=11)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')



class RegistrationFormReceiver(FlaskForm):

    receiver_name = StringField('Receiver Name',
                               validators=[DataRequired(), Length(min=2, max=20)])
    username_rec = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    vat_rec = StringField('VAT (ex. P.IVA)',
                      validators=[DataRequired(), Length(min=0, max=11)])
    email_rec = StringField('Email',
                        validators=[DataRequired(), Email()])
    password_rec = PasswordField('Password', validators=[DataRequired()])
    confirm_password_rec = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password_rec')])
    submit_rec = SubmitField('Sign Up')



class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ForgotForm(FlaskForm):
    email = StringField('Email address',
                       validators=[DataRequired(), Email()])

    email_rec = StringField('Email',
                            validators=[DataRequired(), Email()])
    submit = SubmitField('Send Email')


#-----------------------------------------------------------

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        email = app.Donator.query.filter_by(email=email.data).first()
        if email is None:
            raise ValidationError('There is not an account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')