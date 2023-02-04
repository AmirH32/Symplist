# Imports all the required libraries
import requests, json
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager,login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, EmailField, SelectField, StringField, DateField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from autocorrect import Speller

# Creates an instance of the Flask object 
app = Flask(__name__)

### App setup 


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


### End of App setup


### Models

# Creates a database object using SQLAlchemy
with app.app_context():
    db = SQLAlchemy(app)

# Creates a class for each table entity in the database (object relation mapping)
class User(db.Model, UserMixin):
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

    # Appointments = db.relationship('appointments', backref="Doctor")

    def get_id(self):
        return self.UserID

# class Appointments(db.model):
#     AppointmentID = db.Column(db.Integer, primary_key=True)
#     DoctorID = db.Column(db.Integer, db.Foreignkey('user.UserID'), nullable = False)




### End of models


### Forms


# Uses wtforms to create a form that includes a CRSF_token
class RegisterForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw={"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password."),Length(max=128)], render_kw={"placeholder" : "Password"})
    confirm_Password = PasswordField(label='Confirmed Password', validators=[InputRequired("Confirm your password."),Length(max=128)], render_kw={"placeholder" : "Confirmed Password"})
    Gender = SelectField(choices=[('M', 'Male'),('F', 'Female'),('O', 'Other')],validate_choice=True,render_kw={"placeholder" : "Gender"})
    FirstName = StringField(label='First Name', validators=[InputRequired("Enter your first name."),Length(max=32)], render_kw={"placeholder" : "First Name"})
    Surname = StringField(label='Surname', validators=[InputRequired("Enter your surname."),Length(max=32)], render_kw={"placeholder" : "Surname"})
    ContactNumber = StringField(label='Contact Number', validators=[InputRequired("Enter your contact number."),Length(min=11,max=11)], render_kw={"placeholder" : "Contact Number"})
    Title = StringField(label='Title', validators=[Length(max=32)], render_kw = {"placeholder" : "Title (e.g Mr,Mrs)"})
    DateOfBirth = DateField(label='Date Of Birth', validators=[InputRequired("Enter your date of birth.")], render_kw={"placeholder" : "Date of Birth"})
    Postcode =StringField(label='Postcode',validators=[InputRequired("Enter your postcode."), Length(max=64)],render_kw={"placeholder" : "Postcode"}) 
    Address =StringField(label='Address',validators=[InputRequired("Enter your address"), Length(max=64)],render_kw={"placeholder" : "Address"}) 
    GeneralPractice =StringField(label='General Practice',validators=[InputRequired("Enter your General Practice."), Length(max=64)],render_kw={"placeholder" : "General Practice"})
    AccountType =SelectField(label='Account Type',choices=[('Doctor','Doctor'),('HeadDoctor','Head Doctor'),('Patient','Patient')],validate_choice=True,render_kw={"placeholder" : "Account Type"})
    Submit = SubmitField("Register")

    # Validate_email method raises an error if the email already exists in the database

    def validate_email(self, email):
        existing_email = User.query.filter_by(Email=email.data).first()

        if existing_email:
            flash("User with that email already exists.", category='error')
            # if the Email exists in the User table, the user is notified that the email has been used
            return False

        return True


class LoginForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    Submit = SubmitField("Login")


class ConditionForm(FlaskForm):
    ConditionName = StringField(label='Condition', validators=[InputRequired("Enter the condition"), Length(min=1,max=216)], render_kw={"placeholder" : "Search Conditions..."})
    Submit = SubmitField("Search")

class TreatmentForm(FlaskForm):
    TreatmentName = StringField(label='Medicine', validators=[InputRequired("Enter the treatment"), Length(min=1,max=256)], render_kw={"placeholder" : "Search Treatments..."})
    Submit = SubmitField("Search")

    def Get_Gname_response(self):
        Generic_name = self.TreatmentName.data 
        response = requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.generic_name:{Generic_name}").json()
        if response == '404':
            return False
        else:
            Main_info = response['results'][0]['spl_product_data_elements'][0]
            Ingredients = response['results'][0]['active_ingredient'][0]
            Purpose = response['results'][0]['purpose'][0]
            Usage = response['results'][0]['indications_and_usage'][0]
            Do_not_use = response['results'][0]['do_not_use'][0]
            Ask_doc = response['results'][0]['ask_doctor'][0]
            Ask_pharm = response['results'][0]['ask_doctor_or_pharmacist'][0]
            Stop_use = response['results'][0]['stop_use'][0]
            pregnancy_info = response['results'][0]['pregnancy_or_breast_feeding'][0]
            Dosage = response['results'][0]['dosage_and_administration'][0]
            Storage = response['results'][0]['storage_and_handling'][0]
            Inactive_ingred = response['results'][0]['inactive_ingredient'][0]
            return Main_info, Ingredients, Purpose, Usage, Do_not_use, Ask_doc, Ask_pharm, Stop_use, pregnancy_info, Dosage, Storage, Inactive_ingred

### End of Forms

def Autocorrect(string):
    spell = Speller()
    Autocorrected_string = spell(string)
    return Autocorrected_string

def GetConditionInfo(Condition):
    Response = requests.get(f" https://clinicaltables.nlm.nih.gov/api/conditions/v3/search?terms={Condition}&df=primary_name,consumer_name,info_link_data").json()
    Primary_names = []
    Consumer_names = []
    Condition_links = []
    Conditions = Response[3]
    # Requests from the API and saves the required data that will be outputted to the user
    for Condition_info in Conditions:
        Primary_names.append(Condition_info[0])
        Consumer_names.append(Condition_info[1])
        Condition_links.append(Condition_info[2].split(',')[0])   
    # Creates a list of infos for each condition returned from the API request
    return Primary_names, Consumer_names, Condition_links 


### Views

@app.route('/')
def index():
    return render_template('index.html')
# Renders the index page if the url is '/'


@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    # Instantiates LoginForm

    if form.validate_on_submit():
        user = User.query.filter_by(Email=form.Email.data).first()
        # If the form is valid it queries for the 'User' table where the email is the same as the email posted
        if user:
            if bcrypt.check_password_hash(user.Password, form.Password.data):
                login_user(user, remember=True)
                return redirect(url_for('index'))
                # If the user exists and the hashed password matches the password for that user in the database, the user is logged in and redirected to the index page
            else:
                flash("Incorrect password", category='error')
        else:
            flash(f"{form.Email.data} isn't registered", category='error')
    return render_template('login.html',form=form)
    # If the method is a GET method, the login page is rendered


@app.route('/register', methods=['POST','GET'])
def register():
    form = RegisterForm()
    # Instantiates RegisterForm
    if form.validate_on_submit() and form.validate_email(email=form.Email):
        pass1 = form.Password.data
        confirm_pass1 = form.confirm_Password.data
        # If the form is valid and the email hasn't already been used, the password and confirmed passwords are checked
        if pass1 == confirm_pass1:
            hashed_password = bcrypt.generate_password_hash(form.Password.data)
            email = form.Email.data
            password = hashed_password
            Gender = form.Gender.data
            FirstName = form.FirstName.data
            Surname = form.Surname.data
            ContactNumber = form.ContactNumber.data
            Title = form.Title.data
            DateOfBirth = form.DateOfBirth.data
            Postcode = form.Postcode.data
            Address = form.Address.data.upper()
            GeneralPractice = form.GeneralPractice.data.upper()
            AccountType = form.AccountType.data
            # All data from the from is retrieved from the POST method
            new_User = User(Email=email, Password=password, Gender=Gender, FirstName=FirstName, Surname=Surname, ContactNumber=ContactNumber, Title=Title, DateOfBirth=DateOfBirth, Postcode=Postcode, Address=Address, GeneralPractice=GeneralPractice, AccountType=AccountType)
            db.session.add(new_User)
            db.session.commit()
            # A User object is instantiated with the data retrieved before being added and commited to the database
            return redirect(url_for('login'))
            # The user is redirected to the login screen
        else:
            flash("Password and confirmed password are not the same.",category='error')

    return render_template('register.html', form=form)
    # If the method is a GET request, the register page is rendered and form is passed on to the jinja 2

@app.route("/logout")
@login_required
# login_required decorator, requires a user logged in for the function to work
def logout():
    logout_user()
    return redirect(url_for('index'))
    # Once logged out, the user is redirected to the index page

@app.route("/research", methods=['POST', 'GET'])
def research():
    # Attempts to get the Condition encoded in the url
    Condition = request.args.get('Condition')

    # Instantiates the forms
    Condition_form = ConditionForm()
    Treatment_form = TreatmentForm()

    if Condition_form.validate_on_submit():
        Condition = Condition_form.ConditionName.data
        Corrected_Condition = Autocorrect(Condition)
        # Auto corrects the Condition

        if Corrected_Condition == Condition:
            Corrected_Condition = None

        Primary_names, Consumer_names, Condition_links = GetConditionInfo(Condition)

        return render_template('research.html', Treatmentform=Treatment_form, Condition_form=Condition_form, Primary_names=Primary_names, Consumer_names=Consumer_names, Condition_links=Condition_links, Corrected_Condition=Corrected_Condition)
    
    elif Condition !=None:
        Corrected_Condition = Autocorrect(Condition)
        # Auto corrects the Condition

        if Corrected_Condition == Condition:
            Corrected_Condition = None

        Primary_names, Consumer_names, Condition_links = GetConditionInfo(Condition)

        return render_template('research.html', Treatmentform=Treatment_form, Condition_form=Condition_form, Primary_names=Primary_names, Consumer_names=Consumer_names, Condition_links=Condition_links, Corrected_Condition=Corrected_Condition)

        

    if Treatment_form.validate_on_submit():
        Treatment = Treatment_form.TreatmentName.data()
        Corrected_Treatment = Autocorrect(Treatment)
        
        if Corrected_Treatment == Treatment:
            Corrected_Treatment = None


    return render_template('research.html', Treatmentform=Treatment_form, Condition_form=Condition_form, first_visit=True)

 



### End of Views

if __name__=='__main__':
    app.run(debug=True)

# <!-- from app import app, db
# >>> app.app_context().push()
# >>> db.create_all() 
