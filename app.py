from flask import Flask, render_template, url_for, flash, redirect
from forms import RegistrationFormDonator, RegistrationFormReceiver, LoginForm, RequestResetForm, ResetPasswordForm
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message




# ---------------    DATABASE CONFIG SECTION ------------
app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# -------------- EMAIL SERVER SECTION --------------
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'foodfeed96@gmail.com'
app.config['MAIL_PASSWORD'] = 'babbonatale123'

mail = Mail(app)



posts = [
    {
        'author': 'Corey Schafer',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'April 20, 2018'
    },
    {
        'author': 'Jane Doe',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'April 21, 2018'
    }
]


class Donator(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    user = db.Column(db.String(), unique=True, nullable=False)
    vat = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    passwordDb = db.Column(db.String(60),  nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'donator_id': self.id}).decode('utf-8')


    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            donator_id = s.loads(token)['donator_id']
        except:
            return None
        return Donator.query.get(donator_id)

    def __repr__(self):
        return "Donator('{self.name}', '{self.email}')"



class Receiver(db.Model, UserMixin):
    id_rec = db.Column(db.Integer, primary_key=True)
    name_rec = db.Column(db.String(20), unique=True, nullable=False)
    user_rec = db.Column(db.String())
    vat_rec = db.Column(db.String(11), unique=True, nullable=False)
    email_rec = db.Column(db.String(120), unique=True, nullable=False)
    passwordDb_rec = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return "Receiver('{self.name_rec}', '{self.email_rec}')"





@app.before_first_request
def setup_db():
    db.create_all()

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About')




@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationFormDonator(prefix='don')
    if form.validate_on_submit():
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        donator = Donator(
            name=form.company_name.data,
            user=form.username.data,
            vat=form.vat.data,
            email=form.email.data,
            passwordDb=password
        )
        db.session.add(donator)
        db.session.commit()
        flash(format('Account created for {form.username.data}!'), 'success')
        return redirect(url_for('login'))


    form_rec = RegistrationFormReceiver(prefix='rec')
    if form_rec.validate_on_submit():
        password_rec = bcrypt.generate_password_hash(form_rec.password_rec.data).decode('utf-8')
        receiver = Receiver(
            name_rec=form_rec.receiver_name.data,
            user_rec=form_rec.username_rec.data,
            vat_rec=form_rec.vat_rec.data,
            email_rec=form_rec.email_rec.data,
            passwordDb_rec=password_rec
        )
        db.session.add(receiver)
        db.session.commit()
        flash(format('Account created for {form_rec.username_rec.data}!'), 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form, form_rec=form_rec)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if Donator.query.filter_by(email=form.email.data).first():
            user = Donator.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.passwordDb, form.password.data):
                print('login')
                flash('You have been logged in!', 'success')
                return redirect(url_for('home'))
        elif Receiver.query.filter_by(email_rec=form.email.data).first():
            user = Receiver.query.filter_by(email_rec=form.email.data).first()
            print(user.name_rec)
            if user and bcrypt.check_password_hash(user.passwordDb_rec, form.password.data):
                print('login')
                flash('You have been logged in!', 'success')
                return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            return render_template('login.html', title='Login', form=form)

    return render_template('login.html', title='Login', form=form)




# ------------------ RESET PASSWORD ROUTES AND FUNCTIONS ---------------------------------
def send_reset_email(donator):
    token = donator.get_reset_token()
    msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[donator.email])
    url = url_for('reset_token', token=token, _external=True)
    msg.body = '''To reset your password, visit the following link:
    ''' + url + '''
If you did not make this request then simply ignore this email and no changes will be made.'''
    mail.send(msg)


@app.route('/reset_password', methods=['POST', 'GET'])
def reset_request():
    form = RequestResetForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        donator = Donator.query.filter_by(email=form.email.data).first()
        send_reset_email(donator)
        flash('An email has been send with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['POST', 'GET'])
def reset_token(token):
    form = ResetPasswordForm()
    donator = Donator.verify_reset_token(token)
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if donator is None:
        flash('That is an invalid Token', 'warning')
        return redirect(url_for('reset_request'))
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        donator.passwordDb = hashed_password
        db.session.commit()
        flash('Your password has been updated!! you are now able to login!!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)



if __name__ == '__main__':
    app.run(debug=True)