# Imports all the required libraries
import requests, json
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database1.db'

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
    First_Name = db.Column(db.String(32), nullable = False)
    Surname = db.Column(db.String(32), nullable = False)
    Contact_Number = db.Column(db.String(11), nullable=False)
    Title = db.Column(db.String(32), nullable=True)
    Date_Of_Birth = db.Column(db.Date(), nullable=False)
    Postcode = db.Column(db.String(64), nullable=False)
    Address = db.Column(db.String(64), nullable=False)
    General_Practice = db.Column(db.String(64), nullable=False) 
    Account_Type = db.Column(db.String(32), nullable=False)

    def get_id(self):
        return self.UserID


### End of models


### Forms


# Uses wtforms to create a form that includes a CRSF_token
class RegisterForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw={"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password."),Length(max=128)], render_kw={"placeholder" : "Password"})
    Confirm_Password = PasswordField(label='Confirmed Password', validators=[InputRequired("Confirm your password."),Length(max=128)], render_kw={"placeholder" : "Confirmed Password"})
    Gender = SelectField(choices=[('M', 'Male'),('F', 'Female'),('O', 'Other')],validate_choice=True,render_kw={"placeholder" : "Gender"})
    First_Name = StringField(label='First Name', validators=[InputRequired("Enter your first name."),Length(max=32)], render_kw={"placeholder" : "First Name"})
    Surname = StringField(label='Surname', validators=[InputRequired("Enter your surname."),Length(max=32)], render_kw={"placeholder" : "Surname"})
    Contact_Number = StringField(label='Contact Number', validators=[InputRequired("Enter your contact number."),Length(min=11,max=11)], render_kw={"placeholder" : "Contact Number"})
    Title = StringField(label='Title', validators=[Length(max=32)], render_kw = {"placeholder" : "Title (e.g Mr,Mrs)"})
    Date_Of_Birth = DateField(label='Date Of Birth', validators=[InputRequired("Enter your date of birth.")], render_kw={"placeholder" : "Date of Birth"})
    Postcode =StringField(label='Postcode',validators=[InputRequired("Enter your postcode."), Length(max=64)],render_kw={"placeholder" : "Postcode"}) 
    Address =StringField(label='Address',validators=[InputRequired("Enter your address"), Length(max=64)],render_kw={"placeholder" : "Address"}) 
    General_Practice =StringField(label='General Practice',validators=[InputRequired("Enter your General Practice."), Length(max=64)],render_kw={"placeholder" : "General Practice"})
    Account_Type =SelectField(label='Account Type',choices=[('Doctor','Doctor'),('HeadDoctor','Head Doctor'),('Patient','Patient')],validate_choice=True,render_kw={"placeholder" : "Account Type"})
    Submit = SubmitField("Register")


    # Validate_email method raises an error if the email already exists in the database

    def validate_email(self, email):
        Existing_Email = User.query.filter_by(Email=email.data).first()

        if Existing_Email:
            flash("User with that email already exists.", category='Error')
            # if the Email exists in the User table, the user is notified that the email has been used
            return False

        return True


    
    def Get_Input_Data(self):
        Input_data = {}
        Input_data['Password'] = bcrypt.generate_password_hash(self.Password.data)
        Input_data['Email'] = self.Email.data
        Input_data['Gender'] = self.Gender.data
        Input_data['First_Name'] = self.First_Name.data
        Input_data['Surname'] = self.Surname.data
        Input_data['Contact_Number'] = self.Contact_Number.data
        Input_data['Title'] = self.Title.data
        Input_data['Date_Of_Birth'] = self.Date_Of_Birth.data
        Input_data['Postcode'] = self.Postcode.data
        Input_data['Address'] = self.Address.data.upper()
        Input_data['General_Practice'] = self.General_Practice.data.upper()
        Input_data['Account_Type'] = self.Account_Type.data
        
        return Input_data



class LoginForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    Submit = SubmitField("Login")



class ConditionForm(FlaskForm):
    Condition_Name = StringField(label='Condition', validators=[InputRequired("Enter the condition"), Length(min=1,max=216)], render_kw={"placeholder" : "Search Conditions..."})
    Submit = SubmitField("Search")



class TreatmentForm(FlaskForm):
    Treatment_Name = StringField(label='Medicine', validators=[InputRequired("Enter the treatment"), Length(min=1,max=256)], render_kw={"placeholder" : "Search Treatments..."})
    Submit = SubmitField("Search")

    

### End of Forms


def Autocorrect(string):
    spell = Speller()
    Autocorrected_String = spell(string)
    return Autocorrected_String



def GetConditionInfo(Condition):
    Response = requests.get(f" https://clinicaltables.nlm.nih.gov/api/conditions/v3/search?terms={Condition}&df=primary_name,consumer_name,info_link_data").json()
    print(Response)
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



def Get_Generic_name_Response(Generic_Name):
        try:
            Response = requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.generic_name:{Generic_Name}")
            print(Response)
            Treatment_Data = Get_Treatment_Data(Response.json())
            return Treatment_Data
        except:
            Treatment_Data = Get_Brand_Name_Response(Generic_Name)
            if Treatment_Data == None:
                return None
            else:
                return Treatment_Data   
        
            

def Get_Brand_Name_Response(Brand_Name):
    try:
        Response =  requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.brand_name:{Brand_Name}")
        print(Response)
        Treatment_Data = Get_Treatment_Data(Response.json())
        return Treatment_Data
    except:
        Treatment_Data = Get_Substance_Name_Response(Brand_Name)
        if Treatment_Data == None:
            return None
        else:
            return Treatment_Data
    


def Get_Substance_Name_Response(Substance_Name):
    try:
        Response =  requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.substance_name:{Substance_Name}")
        print(Response)
        Treatment_Data = Get_Treatment_Data(Response.json())
        return Treatment_Data
    except:
        return None
    


def Get_Treatment_Data(Response):
    Treatment_Data = {}
    KeyFields = ['Purpose', 'Usage', 'Dosage', 'Do Not Use', 'Ask a Doctor', 'Ask a Pharmacist or Doctor', 'Stop Usage', 'Pregnancy Information', 'Storage', 'Main Info', 'Ingredients', 'Inactive Ingredients']
    Queries = ['purpose', 'indications_and_usage', 'dosage_and_administration', 'do_not_use', 'ask_doctor', 'ask_doctor_or_pharmacist', 'stop_use', 'pregnancy_or_breast_feeding', 'storage_and_handling', 'spl_product_data_elements', 'active_ingredient', 'inactive_ingredient']
    if len(KeyFields) == len(Queries):
        Treatment_Data['Generic_Name'] = Response['results'][0]['openfda']['generic_name'][0]
        Treatment_Data['Substance_Name'] = Response['results'][0]['openfda']['substance_name'][0]
        for index in range(0, len(KeyFields)):
            try:
                Treatment_Data[KeyFields[index]] = Response['results'][0][Queries[index]][0]
            except:
                pass
    else:
        Treatment_Data = None
    return Treatment_Data



### Views


@app.route('/')
def Index():
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
                return redirect(url_for('Index'))
                # If the user exists and the hashed password matches the password for that user in the database, the user is logged in and redirected to the Index page
            else:
                flash("Incorrect password", category='Error')
        else:
            flash(f"{form.Email.data} isn't registered", category='Error')
    return render_template('login.html',form=form)
    # If the method is a GET method, the login page is rendered



@app.route('/register', methods=['POST','GET'])
def register():
    form = RegisterForm()
    # Instantiates RegisterForm
    if form.validate_on_submit() and form.validate_email(email=form.Email):
        password = form.Password.data
        confirm_password = form.Confirm_Password.data
        # If the form is valid and the email hasn't already been used, the password and confirmed passwords are checked
        if password == confirm_password:
            Input_data = form.Get_Input_Data()
            # All data from the from is retrieved from the POST method
            new_User = User(Email=Input_data['Email'], Password=Input_data['Password'], Gender=Input_data['Gender'], First_Name=Input_data['First_Name'], Surname=Input_data['Surname'], Contact_Number=Input_data['Contact_Number'], Title=Input_data['Title'], Date_Of_Birth=Input_data['Date_Of_Birth'], Postcode=Input_data['Postcode'], Address=Input_data['Address'], General_Practice=Input_data['General_Practice'], )
            db.session.add(new_User)
            db.session.commit()
            # A User object is instantiated with the data retrieved before being added and commited to the database
            return redirect(url_for('login'))
            # The user is redirected to the login screen
        else:
            flash("Password and confirmed password are not the same.",category='Error')

    return render_template('register.html', form=form)
    # If the method is a GET request, the register page is rendered and form is passed on to the jinja 2



@app.route("/logout")
@login_required
# login_required decorator, requires a user logged in for the function to work
def logout():
    logout_user()
    return redirect(url_for('Index'))
    # Once logged out, the user is redirected to the index page



@app.route("/research", methods=['POST', 'GET'])
def research():
    # Attempts to get the Condition encoded in the url
    Condition = request.args.get('Condition')
    Treatment = request.args.get('Treatment')

    # Instantiates the forms
    Condition_form = ConditionForm()
    Treatment_form = TreatmentForm()

    if Condition_form.validate_on_submit():
        Condition = Condition_form.Condition_Name.data
        Corrected_Condition = Autocorrect(Condition)
        # Auto corrects the Condition

        if Corrected_Condition == Condition:
            Corrected_Condition = None

        Primary_names, Consumer_names, Condition_links = GetConditionInfo(Condition)

        return render_template('research.html', Treatment_form=Treatment_form, Condition_form=Condition_form, Primary_names=Primary_names, Consumer_names=Consumer_names, Condition_links=Condition_links, Corrected_Condition=Corrected_Condition, first_Treatment_visit = True)
    
    elif Condition !=None:
        Corrected_Condition = Autocorrect(Condition)
        # Auto corrects the Condition

        if Corrected_Condition == Condition:
            Corrected_Condition = None

        Primary_names, Consumer_names, Condition_links = GetConditionInfo(Condition)

        return render_template('research.html', Treatment_form=Treatment_form, Condition_form=Condition_form, Primary_names=Primary_names, Consumer_names=Consumer_names, Condition_links=Condition_links, Corrected_Condition=Corrected_Condition, first_Treatment_visit = True)

        

    if Treatment_form.validate_on_submit():
        Treatment = Treatment_form.Treatment_Name.data
        Corrected_Treatment = Autocorrect(Treatment)
        
        if Corrected_Treatment == Treatment:
            Corrected_Treatment = None
        
        Treatment_Data = Get_Generic_name_Response(Treatment)
        return render_template('research.html', Treatment_form=Treatment_form, Condition_form=Condition_form, Treatment_Data = Treatment_Data, Corrected_Treatment = Corrected_Treatment, first_Condition_visit = True)
    
    elif Treatment != None:
        Corrected_Treatment = Autocorrect(Treatment)

        if Corrected_Treatment == Treatment:
            Corrected_Treatment = None

        Treatment_Data = Get_Generic_name_Response(Treatment)

        return render_template('research.html', Treatment_form=Treatment_form, Condition_form=Condition_form, Treatment_Data = Treatment_Data, Corrected_Treatment = Corrected_Treatment, first_Condition_visit = True)
        
        
    return render_template('research.html', Treatment_form=Treatment_form, Condition_form=Condition_form, first_Treatment_visit=True, first_Condition_visit = True)


@app.route("/booking", methods=['POST', 'GET'])
def booking():
    return render_template('booking.html')



### End of Views

if __name__=='__main__':
    app.run(debug=True)

# from Symplist import app, db
# app.app_context().push()
# db.create_all() 
