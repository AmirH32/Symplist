# Imports all the required libraries
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager,login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, EmailField, SelectField, StringField, DateField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt

# Creates an instance of the Flask object 
app = Flask(__name__)

# Creates an instance of the bcrypt object - allowing for password encryption and hashing
bcrypt = Bcrypt(app)

# Sets an encryption key for the flask framework
app.config['SECRET_KEY'] = 'N`5z!B}4uftw=w$S)}6=p(PVZ`:VN*m'
# Sets a location and file for the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_User(id):
    return User.query.get(int(id))

# Creates a database object using SQLAlchemy
with app.app_context():
    db = SQLAlchemy(app)

# Creates a class for each table entity in the database (object relation mapping)
class User(db.Model):
    UserID = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String(256), nullable=False, unique=True)
    Password = db.Column(db.String(128), nullable=False)
    Gender = db.Column(db.String(1), nullable=False)
    FirstName = db.Column(db.String(32), nullable = False)
    Surname = db.Column(db.String(32), nullable = False)
    ContactNumber = db.Column(db.String(11), nullable=False)
    Title = db.Column(db.String(32), nullable=True)
    DateOfBirth = db.Column(db.Date(), nullable=False)
    Postcode = db.Column(db.String(64), nullable=False)
    Address = db.Column(db.String(64), nullable=False)
    GeneralPractice = db.Column(db.String(64), nullable=False)
    AccountType = db.Column(db.String(16), nullable=False)

# Uses wtforms to create a form that includes a CRSF_token
class RegisterForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw={"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password."),Length(max=128)], render_kw={"placeholder" : "Password"})
    confirm_Password = PasswordField(label='Confirmed Password', validators=[InputRequired("Confirm your password."),Length(max=128)], render_kw={"placeholder" : "Confirmed Password"})
    Gender = SelectField(choices=[('M', 'Male'),('F', 'Female'),('O', 'Other')],validate_choice=True,render_kw={"placeholder" : "Gender"})
    FirstName = StringField(label='First Name', validators=[InputRequired("Enter your first name."),Length(max=32)], render_kw={"placeholder" : "First Name"})
    Surname = StringField(label='Surname', validators=[InputRequired("Enter your surname."),Length(max=32)], render_kw={"placeholder" : "Surname"})
    ContactNumber = StringField(label='ContactNumber', validators=[InputRequired("Enter your contact number."),Length(min=11,max=11)], render_kw={"placeholder" : "Contact Number"})
    Title = StringField(label='Title', validators=[Length(max=32)], render_kw = {"placeholder" : "Title (e.g Mr,Mrs)"})
    DateOfBirth = DateField(label='Date Of Birth', validators=[InputRequired("Enter your date of birth.")], render_kw={"placeholder" : "Date of Birth"})
    Postcode =StringField(label='Postcode',validators=[InputRequired("Enter your postcode."), Length(max=64)],render_kw={"placeholder" : "Postcode"}) 
    Address =StringField(label='Address',validators=[InputRequired("Enter your address"), Length(max=64)],render_kw={"placeholder" : "Address"}) 
    GeneralPractice =StringField(label='General Practice',validators=[InputRequired("Enter your General Practice."), Length(max=64)],render_kw={"placeholder" : "General Practice"})
    AccountType =SelectField(choices=[('Doctor','Doctor'),('HeadDoctor','Head Doctor'),('Patient','Patient')],validate_choice=True,render_kw={"placeholder" : "Account Type"})
    Submit = SubmitField("Register")

    # Validate_email method raises an error if the email already exists in the database

    def validate_email(self, email):
        existing_email = User.query.filter_by(Email=email.data).first()

        if existing_email:
            print('Email exists')
            flash("User with that email already exists.", category='error')
            return False

        return True


class LoginForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    Submit = SubmitField("Login")

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(Email=form.Email.data).first()
        if user:
            print(form.Password.data)
            if bcrypt.check_password_hash(user.Password, form.Password.data):
                login_user(User, remember=True)
                return redirect(url_for('index'))
            else:
                flash("Incorrect password", category='error')
        else:
            flash("That email doesn't exist", category='error')
    return render_template('login.html',form=form)

@app.route('/register', methods=['POST','GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit() and form.validate_email(email=form.Email):
        print("hello")
        pass1 = form.Password.data
        confirm_pass1 = form.confirm_Password.data
        if pass1 == confirm_pass1:
            hashed_password = bcrypt.generate_password_hash(form.Password.data)
            print(hashed_password)
            email = form.Email.data
            password = hashed_password
            Gender = form.Gender.data
            FirstName = form.FirstName.data
            Surname = form.Surname.data
            ContactNumber = form.ContactNumber.data
            Title = form.Title.data
            DateOfBirth = form.DateOfBirth.data
            Postcode = form.Postcode.data
            Address = form.Address.data
            GeneralPractice = form.GeneralPractice.data
            AccountType = form.AccountType.data
            # new_User = User()
            # db.session.add(new_User)
            # db.session.commit()
            return redirect(url_for('login'))
        else:
            flash("Password and confirmed password are not the same.",category='error')

    return render_template('register.html', form=form)

if __name__=='__main__':
    app.run(debug=True)

# <!-- from app import app, db
# >>> app.app_context().push()
# >>> db.create_all() 