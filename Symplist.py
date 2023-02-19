# Imports all the required libraries
import requests, json
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager,login_user, logout_user, login_required
from flask_rbac import RBAC, RoleMixin
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, EmailField, SelectField, StringField, DateField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from autocorrect import Speller
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import time

# Creates an instance of the Flask object 
app = Flask(__name__)

### App setup 


# Creates an instance of the bcrypt object - allowing for password encryption and hashing
bcrypt = Bcrypt(app)

rbac = RBAC(app)


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

roles_users = db.Table('roles_users',
                        db.Column('user_id', db.Integer,
                        db.ForeignKey('user.UserID')),
                        db.Column('role_id', db.Integer,
                        db.ForeignKey('role.id')))


class User(db.Model, UserMixin):
    UserID = db.Column(db.Integer, primary_key=True, unique = True)
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
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users'), lazy='joined')

    def get_id(self):
        return self.UserID
    
    def add_role(self, name):
        roles = Role.query.all()
        for role in roles:
            if name == role.name:
                self.roles.append(role)

rbac.set_user_model(User)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(16), unique=True)

    def __init__(self, name):
        RoleMixin.__init__(self)
        self.name = name    

    @staticmethod
    def get_by_name(name):
        return Role.query.filter_by(name=name).first()

rbac.set_role_model(Role)   

class Appointments(db.Model):
    AppointmentID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    DoctorID = db.Column(db.Integer, db.ForeignKey('user.UserID'))
    Doctor = relationship("User", foreign_keys=[DoctorID], backref="Doctors")
    PatientID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable = False)
    Patient = relationship("User", foreign_keys=[PatientID], backref="Patients")
    Start_Date = db.Column(db.DateTime(), nullable=False)
    End_Date = db.Column(db.DateTime(), nullable=False) 





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

class StudiesForm(FlaskForm):
    Study_Topic = StringField(label='Medicine', validators=[InputRequired("Enter the treatment"), Length(min=1,max=256)], render_kw={"placeholder" : "Search Studies..."})
    Submit = SubmitField("Search")

    

### End of Forms



def Autocorrect(string):
    spell = Speller()
    Autocorrected_String = spell(string)
    return Autocorrected_String



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



def Get_Generic_name_Response(Generic_Name):
        try:
            Response = requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.generic_name:{Generic_Name}")
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

def Get_Appointments_Doctor_Info():
    pending_appointments =  Appointments.query.filter_by(DoctorID=None)
    booked_appointments = Appointments.query.filter(Appointments.DoctorID !=None)
    Doctor_info = []
    for appointment in booked_appointments:
        user = User.query.filter_by(UserID=appointment.DoctorID).first()
        Doctor_info.append([user.Surname,user.Title])
    return pending_appointments, booked_appointments, Doctor_info

def Get_Appointments_Patient_Info():
    pending_appointments =  Appointments.query.filter_by(DoctorID=None)
    booked_appointments = Appointments.query.filter(Appointments.DoctorID !=None)
    Patient_info = []
    for appointment in booked_appointments:
        user = User.query.filter_by(UserID=appointment.PatientID).first()
        Patient_info.append([user.Surname,user.Title])
    return pending_appointments, booked_appointments, Patient_info

def get_study_data(Study_Topic):
    IDs = []
    Response = requests.get(f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term=science[journal]+AND+{Study_Topic}")
    response_xml_as_string = Response.content
    responseXml = ET.fromstring(response_xml_as_string)
    testId = responseXml.find('IdList')
    Studies = []
    for ID in testId:
        IDs.append(ID.text)

    for ID in IDs:
        Response = requests.get(f"https://www.ncbi.nlm.nih.gov/pmc/utils/idconv/v1.0?tool=my_tool&email=amirhassanali2610@gmail.com.com&ids={ID}")
        response_xml_as_string = Response.content
        responseXml = ET.fromstring(response_xml_as_string)
        try:
            pmcid = responseXml[1].attrib['pmcid']
            time.sleep(2)
            response = requests.get(f"https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/{pmcid}/unicode").json()
            Studies.append([response['documents'][0]['passages'], pmcid])
        except:
            print('no pmcid')

    return Studies



### Views

@app.context_processor
def inject_role():
    try:
        user_ID = session["_user_id"]
        role = db.session.query(Role).join(roles_users, User).filter(User.UserID == user_ID).first()
    except:
        role = None
    return dict(role=role, message='hello')

@app.route('/')
def Index():
    try:
        user_ID = session["_user_id"]
        role = db.session.query(Role).join(roles_users, User).filter(User.UserID == user_ID).first()
    except:
        role = None
    return render_template('index.html',role=role)
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
            new_User = User(Email=Input_data['Email'], Password=Input_data['Password'], Gender=Input_data['Gender'], First_Name=Input_data['First_Name'], Surname=Input_data['Surname'], Contact_Number=Input_data['Contact_Number'], Title=Input_data['Title'], Date_Of_Birth=Input_data['Date_Of_Birth'], Postcode=Input_data['Postcode'], Address=Input_data['Address'], General_Practice=Input_data['General_Practice'])
            # Role instantiation
            new_User.add_role(Input_data['Account_Type'])
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

# @rbac.allow(['Doctor'], methods=['POST, GET'])
@app.route("/Booking", methods=['POST', 'GET'])
def booking():
    pending_appointments, booked_appointments, Doctor_info = Get_Appointments_Doctor_Info()
    return render_template('booking.html', pending_appointments=pending_appointments, booked_appointments=booked_appointments, Doctor_info=Doctor_info)
    

@app.route("/Add_Appointment", methods=['POST']) 
def insert_appointment():
    if request.method == 'POST':
        date = request.form['date'].split(" (",1)[0]
        user_ID = request.form['current_user_ID']
        date_datetime = datetime.strptime(date, '%a %b %d %Y %H:%M:%S %Z%z')
        new_Appointment = Appointments(PatientID=user_ID, Start_Date=date_datetime, End_Date=date_datetime + timedelta(days=1) )
        db.session.add(new_Appointment)
        db.session.commit()
        return redirect(url_for('booking'))
    
@app.route("/Delete_Appointment", methods=['POST']) 
def delete_appointment():
    if request.method == 'POST':
        AppointmentID = request.form['id']
        Appointments.query.filter_by(AppointmentID=AppointmentID).delete()
        db.session.commit()
        return redirect(url_for('booking'))

@app.route("/Appointments") 
def View_appointments():
    pending_appointments, booked_appointments, Patient_info = Get_Appointments_Patient_Info()
    return render_template('appointments.html', pending_appointments=pending_appointments, booked_appointments=booked_appointments, Patient_info = Patient_info)

@app.route("/take_appointment", methods=['POST']) 
def take_appointment():
    if request.method == 'POST':
        AppointmentID = request.form['id']
        Appointment =  Appointments.query.filter_by(AppointmentID=AppointmentID).first()
        Appointment.DoctorID = session["_user_id"]
        db.session.commit()
        return redirect(url_for('View_appointments'))
    
@app.route("/Update_Appointment", methods=['POST']) 
def Update_Appointment():
    if request.method == 'POST':
        AppointmentID = request.form['Appointment_ID']
        start_date = request.form['start_date'].split(" (",1)[0]
        end_date = request.form['end_date'].split(" (",1)[0]
        start_datetime = datetime.strptime(start_date, '%a %b %d %Y %H:%M:%S %Z%z')
        end_datetime = datetime.strptime(end_date, '%a %b %d %Y %H:%M:%S %Z%z')
        print(start_datetime)
        Appointment =  Appointments.query.filter_by(AppointmentID=AppointmentID).first()
        Appointment.Start_Date = start_datetime
        Appointment.End_Date = end_datetime
        db.session.commit()
        return redirect(url_for('View_appointments'))
    
@app.route("/studies", methods=['GET','POST']) 
def Studies():
    Study_Topic = request.args.get('Study')
    pmcid = request.args.get('pmcid')
    Studies_Form = StudiesForm()

    if Studies_Form.validate_on_submit():
        Study_Topic = Studies_Form.Study_Topic.data
        Corrected_Study = Autocorrect(Study_Topic)

        if Corrected_Study == Study_Topic:
            Corrected_Study = None

        Studies = get_study_data(Study_Topic)
        return render_template('studies.html', Corrected_Study = Corrected_Study, Studies_Form = Studies_Form, Studies=Studies)

    elif Study_Topic !=None:
        Corrected_Study = Autocorrect(Study_Topic)
        if Corrected_Study == Study_Topic:
            Corrected_Study = None

        Studies = get_study_data(Study_Topic)
        return render_template('studies.html', Corrected_Study = Corrected_Study, Studies_Form = Studies_Form, Studies=Studies)

    elif pmcid != None:
        response = requests.get(f"https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/{pmcid}/unicode").json()
        study_content = response['documents'][0]['passages']
        return render_template('study.html',study_content=study_content)

    return render_template('studies.html',Studies_Form = Studies_Form)

@app.route("/messages", methods=['GET']) 
def messages():
    return render_template('messages.html')


if __name__=='__main__':
    app.run(host="0.0.0.0", debug=True)

# from Symplist import app, db
# app.app_context().push()
# db.create_all() 
