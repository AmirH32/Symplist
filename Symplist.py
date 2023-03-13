# Imports all the required libraries
import requests, json
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, EmailField, SelectField, StringField, DateField, TextAreaField, HiddenField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from autocorrect import Speller
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import time
import re
from functools import wraps

### App setup 


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
    return Users.query.get(int(id))


### End of App setup


### Models

# Creates a database object using SQLAlchemy
with app.app_context():
    db = SQLAlchemy(app)

# Creates a class for each table entity in the database (object relation mapping)

roles_users = db.Table('roles_users',
                        db.Column('user_id', db.Integer,
                        db.ForeignKey('users.UserID')),
                        db.Column('role_id', db.Integer,
                        db.ForeignKey('roles.RoleID'))
                        )


class Users(db.Model, UserMixin):
    UserID = db.Column(db.Integer, primary_key=True, unique = True, nullable=False)
    Email = db.Column(db.String(256), nullable=False, unique=True)
    Password = db.Column(db.String(128), nullable=False)
    Gender = db.Column(db.String(1), nullable=False)
    First_Name = db.Column(db.String(32), nullable = False)
    Surname = db.Column(db.String(32), nullable = False)
    Contact_Number = db.Column(db.String(11), nullable=False)
    Title = db.Column(db.String(32), nullable=False)
    Date_Of_Birth = db.Column(db.Date(), nullable=False)
    Postcode = db.Column(db.String(64), nullable=False)
    Address = db.Column(db.String(64), nullable=False)
    General_Practice = db.Column(db.String(64), nullable=False) 
    roles = db.relationship('Roles', secondary='roles_users', backref=db.backref('users'), lazy='joined')
    # Creates a relationship between the roles and Users table using the roles_users table to get the role based on the UserID

    def get_id(self):
        # Returns the user's ID
        return self.UserID

    def add_role(self, role_name):
        role = Roles.get_by_name(role_name)
        if role:
            # if the role exists it appends the role to the user by adding its ID to the user_roles table alongside the User's ID
            self.roles.append(role)
    

class Roles(db.Model):
    RoleID = db.Column(db.Integer, primary_key=True, unique=True)
    Role_Name = db.Column(db.String(16), unique=True)

    @staticmethod
    def get_by_name(role_name):
        return Roles.query.filter_by(Role_Name=role_name).first()


class Appointments(db.Model):
    AppointmentID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    DoctorID = db.Column(db.Integer, db.ForeignKey('users.UserID'))
    PatientID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    Start_Date = db.Column(db.DateTime(), nullable=False)
    End_Date = db.Column(db.DateTime(), nullable=False) 


class Conversations(db.Model):
    ConversationID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    DoctorID = db.Column(db.Integer, db.ForeignKey('users.UserID'))
    PatientID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    Status = db.Column(db.String(8), nullable=False)
    MessageID = db.Column(db.Integer, db.ForeignKey('messages.MessageID'))

class Messages(db.Model):   
    MessageID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    SenderID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    ConversationID = db.Column(db.Integer, db.ForeignKey('conversations.ConversationID'), nullable=False)
    Date = db.Column(db.DateTime(), nullable=False)
    Content = db.Column(db.String(512), nullable=False)

class Prescriptions(db.Model):
    PrescriptionID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    PatientID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    DoctorID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    Date = db.Column(db.DateTime(), nullable=False)
    Treatment = db.Column(db.String(64), nullable=False)
    Dosage = db.Column(db.String(256), nullable=False)
    Frequency = db.Column(db.String(256), nullable=False)

class Referrals(db.Model):
    ReferralID = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    PatientID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    DoctorID = db.Column(db.Integer, db.ForeignKey('users.UserID'), nullable = False)
    Date = db.Column(db.DateTime(), nullable=False)
    Details = db.Column(db.String(512), nullable=False)
    Description = db.Column(db.String(512), nullable=False)



### End of models


### Forms


# Uses wtforms to create a form that includes a CRSF_token
class RegisterForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw={"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password."),Length(min=8,max=128)], render_kw={"placeholder" : "Password"})
    Confirm_Password = PasswordField(label='Confirmed Password', validators=[InputRequired("Confirm your password."),Length(min=8,max=128)], render_kw={"placeholder" : "Confirmed Password"})
    Gender = SelectField(choices=[('M', 'Male'),('F', 'Female'),('O', 'Other')],validate_choice=True,validators=[InputRequired("Pick a gender.")],render_kw={"placeholder" : "Gender"})
    First_Name = StringField(label='First Name', validators=[InputRequired("Enter your first name."),Length(max=32)], render_kw={"placeholder" : "First Name"})
    Surname = StringField(label='Surname', validators=[InputRequired("Enter your surname."),Length(max=32)], render_kw={"placeholder" : "Surname"})
    Contact_Number = StringField(label='Contact Number', validators=[InputRequired("Enter your contact number."),Length(min=11,max=11)], render_kw={"placeholder" : "Contact Number"})
    Title = StringField(label='Title', validators=[InputRequired("Enter your title."),Length(max=32)], render_kw = {"placeholder" : "Title (e.g Mr,Mrs)"})
    Date_Of_Birth = DateField(label='Date Of Birth', validators=[InputRequired("Enter your date of birth.")], render_kw={"placeholder" : "Date of Birth"})
    Postcode =StringField(label='Postcode',validators=[InputRequired("Enter your postcode."), Length(max=64)],render_kw={"placeholder" : "Postcode"}) 
    Address =StringField(label='Address',validators=[InputRequired("Enter your address"), Length(max=64)],render_kw={"placeholder" : "Address"}) 
    General_Practice =StringField(label='General Practice',validators=[InputRequired("Enter your General Practice."), Length(max=64)],render_kw={"placeholder" : "General Practice"})
    Account_Type =SelectField(label='Account Type',choices=[('Doctor','Doctor'),('Patient','Patient')],validators=[InputRequired("Pick an account type.")],validate_choice=True,render_kw={"placeholder" : "Account Type"})
    Submit = SubmitField("Register")


    # Validate_email method raises an error if the email already exists in the database

    def __validate_email(self, email):
        existing_user_with_email = Users.query.filter_by(Email=email.data).first()
        # Queries User table for when its Email field is the same as the email entered

        if existing_user_with_email:
            flash("The email has already been registered.", category='Error')
            # if the Email exists in the User table, the user is notified that the email has been used
            return False

        return True

    def __validate_password(self):
        password = self.Password.data
        confirm_password = self.Confirm_Password.data
        # The password and confirmed passwords are checked against each other
        if password != confirm_password:
            flash("Password and confirmed password are not the same.",category='Error')
            return False
        # If confirmed password and password are not the same, an error message is flashed
        elif re.search("[!@#$%^&*()_=|';:,.?/~`]" , password) == None:
            flash("Password must contain a special character",category='Error')
            return False
        # If the password has no special characters, an error message is flashed
        elif re.search("[0-9]" , password) == None:
            flash("Password must contain a digit",category='Error')
            return False
        # If the password has digits, an error message is flashed
        elif re.search("[A-Z]" , password) == None:
            flash("Password must contain a capital letter",category='Error')
            return False
        # If the password has capital letters, an error message is flashed
        else:
            return True
        
    def __check_fields_for_digits(self):
        if check_for_digits(self.First_Name.data):
            flash("First name cannot contain digits.")
            return True
        elif check_for_digits(self.Surname.data):
            flash("surname cannot contain digits.")
            return True
        elif check_for_digits(self.Title.data):
            flash("Title cannot contain digits.")
            return True
        elif check_for_digits(self.General_Practice.data):
            flash("General Practice cannot contain digits.")
            return True
        # Checks the First name, Surname, Title and general practice for digits
    
    def __check_fields_for_letters(self):
        if check_for_letters(self.Contact_Number.data.upper()):
            flash("Contact number cannot contain letters.")
            return True
        # Checks the contact number for letters
    
    def __validate_date_of_birth(self):
        DAYS_PER_YEAR = 365.2425
        date_of_birth = self.Date_Of_Birth.data
        if date_of_birth > datetime.today().date():
            # Checks that the date of birth isn't in the future
            flash("You cannot be born in the future.")
            return False
        elif date_of_birth < (datetime.today() - timedelta(days=(140*DAYS_PER_YEAR))).date():
            # Checks that the date of birth isn't more than 140 years ago (oldest person as of now was 122)
            flash("You cannot be more than 140 years old.")
            return False
        else:
            return True

    def validate_fields(self):
        valid = True
        if self.__validate_password() == False:
            valid = False
        # If the password isn't validated, return false
        elif self.__check_fields_for_digits():
            valid = False
        # If the letter fields contain digits, return false
        elif self.__check_fields_for_letters():
            valid = False
        # If the digit fields contain letters, return false
        elif self.__validate_email(self.Email) == False:
            valid = False
        # If the email isn't valid, return false
        elif self.__validate_date_of_birth() == False:
            valid = False
        else:
            pass
        return valid

       
    
    def get_register_form_data(self):
        input_data = {}
        input_data['Password'] = bcrypt.generate_password_hash(self.Password.data)
        input_data['Email'] = self.Email.data
        input_data['Gender'] = self.Gender.data
        input_data['First_Name'] = self.First_Name.data
        input_data['Surname'] = self.Surname.data
        input_data['Contact_Number'] = self.Contact_Number.data
        input_data['Title'] = self.Title.data
        input_data['Date_Of_Birth'] = self.Date_Of_Birth.data
        input_data['Postcode'] = self.Postcode.data.upper()
        input_data['Address'] = self.Address.data.upper()
        # Stores postcode and address uppercase to avoid confusion
        input_data['General_Practice'] = self.General_Practice.data.upper().strip(' ')
        # Stores general practice upper case without spaces to sanitise the data and reduce ambiguity
        input_data['Account_Type'] = self.Account_Type.data
        # Stores all the register form fields in a dictionary
        
        return input_data



class LoginForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    Submit = SubmitField("Login")

    def check_password(self, user):
        if bcrypt.check_password_hash(user.Password, self.Password.data):
            # Checks the password entered against the user's password
            return True
        else:
            return False
            # Returns an "Incorrect password" flash message to the jinja which can then be rendered
    




class ConditionForm(FlaskForm):
    Condition_Name = StringField(label='Condition', validators=[InputRequired("Enter the condition"), Length(min=1,max=216)], render_kw={"placeholder" : "Search Conditions..."})
    Submit = SubmitField("Search")



class TreatmentForm(FlaskForm):
    Treatment_Name = StringField(label='Medicine', validators=[InputRequired("Enter the treatment"), Length(min=1,max=256)], render_kw={"placeholder" : "Search Treatments..."})
    Submit = SubmitField("Search")



class StudiesForm(FlaskForm):
    Study_Topic = StringField(label='Medicine', validators=[InputRequired("Enter the treatment"), Length(min=1,max=256)], render_kw={"placeholder" : "Search studies..."})
    Submit = SubmitField("Search")


class MessageForm(FlaskForm):
    Contents = TextAreaField(label='Message_contents', validators=[InputRequired("Enter your message"), Length(min=1,max=512)], render_kw={"placeholder" : "Message..."})
    Submit = SubmitField("Submit")

class PrescriptionForm(FlaskForm):
    Treatment = TextAreaField(label='Treatment', validators=[InputRequired("Enter the treatment"), Length(min=1,max=64)], render_kw={"placeholder" : "Enter the treatment here..."})
    Dosage = TextAreaField(label='Dosage', validators=[InputRequired("Enter the dosage"), Length(min=1,max=256)], render_kw={"placeholder" : "Enter the dosage here..."})
    Frequency = TextAreaField(label='Frequency', validators=[InputRequired("Enter the frequency"), Length(min=1,max=256)], render_kw={"placeholder" : "Enter the frequency here..."})
    PatientID = HiddenField("PatientID")
    Submit = SubmitField("Submit")

class ReferralForm(FlaskForm):
    Details = TextAreaField(label='Details', validators=[InputRequired("Enter the Details"), Length(min=1,max=512)], render_kw={"placeholder" : "Enter the referral details here..."})
    Description = TextAreaField(label='Description', validators=[InputRequired("Enter the Details"), Length(min=1,max=512)], render_kw={"placeholder" : "Enter the referral description here..."})
    Patientid = HiddenField("PatientID")
    Submit = SubmitField("Submit")

### End of Forms



### Functions

def autocorrect(string):
    spell = Speller()
    # Instantiates the speller object from the imported library
    autocorrected_string = spell(string)
    # Uses the spell object to auto correct the string
    return autocorrected_string
    # Returns the autocorrected string

def get_current_id():
    user_id = session["_user_id"]
    # Uses session to get the user id using the _user_id key
    return user_id
    # Returns the user ID

def get_user_role(user_id):
    role = db.session.query(Roles).join(roles_users, Users).filter(Users.UserID == user_id).first()
    # Queries the database for the Role by joining the roles_users and Users table where User.UserID is equal to user_id in the roles_users table and collects the first instance of this
    return role
    # Returns the role

def add_to_database(record):
    db.session.add(record)
    db.session.commit()

def check_for_digits(string):
    digit_found = re.search("\d", string)
    # Uses regular expression to search the string for any occurrence of a digit
    if digit_found == None:
        return False
        # If no digits are found return false
    else:
        return True
        # If there are digits return true

def check_for_letters(string):
    letter_found = re.search("[A-Z]", string)
    # Uses regular expression to search the string for any occurrence of a letter
    if letter_found == None:
        return False
        # If no letters are found return false
    else:
        return True
        # If there are letters return true

def get_condition_info(condition):
    response = requests.get(f" https://clinicaltables.nlm.nih.gov/api/conditions/v3/search?terms={condition}&df=primary_name,consumer_name,info_link_data").json()
    primary_names = []
    consumer_names = []
    condition_links = []
    conditions = response[3]
    # Requests from the API and saves the required data that will be outputted to the user
    for condition_info in conditions:
        primary_names.append(condition_info[0])
        consumer_names.append(condition_info[1])
        condition_links.append(condition_info[2].split(',')[0])   
    # Creates a list of infos for each condition returned from the API request
    return primary_names, consumer_names, condition_links 

def get_treatment_info(treatment):
    treatment_data = get_generic_name_response(treatment)
    return treatment_data

def get_generic_name_response(generic_name):
        try:
            response = requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.generic_name:{generic_name}")
            treatment_data = get_treatment_data(response.json())
            return treatment_data
            # Attempts to get and return the Treatment data for a generic name search of the FDA API
        except:
            treatment_data = get_brand_name_response(generic_name)
            # If it fails to get any information from the FDA generic name API then it calls the get_brand_name_response() function
            if treatment_data == None:
                return None
            # If no treatment data is returned from all searches, None is returned
            else:
                return treatment_data   
            # Returns treatment data if get_brand_name_response() returns treatment data
        
            

def get_brand_name_response(brand_name):
    try:
        response =  requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.brand_name:{brand_name}")
        #  Attempts to get and return the Treatment data for a brand name search of the FDA API
        treatment_data = get_treatment_data(response.json())
        return treatment_data
    except:
        treatment_data = get_substance_name_response(brand_name)
        # If it fails to get any information from the FDA generic name API then it calls the get_substance_name_response() function
        if treatment_data == None:
            return None
        # If no treatment data is returned from the search, None is returned
        else:
            return treatment_data
        # Returns treatment data if get_substance_name_response() returns treatment data
    


def get_substance_name_response(substance_name):
    try:
        response =  requests.get(f"https://api.fda.gov/drug/label.json?search=openfda.substance_name:{substance_name}")
         #  Attempts to get and return the Treatment data for a substance name search of the FDA API
        treatment_data = get_treatment_data(response.json())
        return treatment_data
    except:
        return None
        # If no treatment data is returned from the search, None is returned
    


def get_treatment_data(response):
    treatment_data = {}
    KEY_FIELDS = ['Purpose', 'Usage', 'Dosage', 'Do Not Use', 'Ask a Doctor', 'Ask a Pharmacist or Doctor', 'Stop Usage', 'Pregnancy Information', 'Storage', 'Main Info', 'Ingredients', 'Inactive Ingredients']
    QUERIES = ['purpose', 'indications_and_usage', 'dosage_and_administration', 'do_not_use', 'ask_doctor', 'ask_doctor_or_pharmacist', 'stop_use', 'pregnancy_or_breast_feeding', 'storage_and_handling', 'spl_product_data_elements', 'active_ingredient', 'inactive_ingredient']
    # QUERIES stores the keys to be extracted from the json returned
    # KEY_FIELDS stores the keys to be appended to the Treatent_Data dictionary

    if len(KEY_FIELDS) == len(QUERIES):
        # As long as there are an equal amount KEY_FIELDS to QUERIES, the code is run
        try:
            treatment_data['Generic_Name'] = response['results'][0]['openfda']['generic_name'][0]
            treatment_data['Substance_Name'] = response['results'][0]['openfda']['substance_name'][0]
            # Gets and stores the generic and substance name seperately since they are located at a different part of the JSON response
            for index in range(0, len(KEY_FIELDS)):
                try:
                    treatment_data[KEY_FIELDS[index]] = response['results'][0][QUERIES[index]][0]
                    # Tries to append the key to treatment_data with the appropriate value in the JSON response
                except:
                    # If this is not possible, i.e. the response lacks that key, the loop is passed
                    pass
        except:
            treatment_data = None
    else:
        treatment_data = None
        # If there is not an equal amount of KEY_FIELDS to QUERIES, treatment data is returned as None
    return treatment_data

def get_appointments():
    booked_appointments = Appointments.query.filter(Appointments.DoctorID !=None).all()
    # Gets all booked appointments by querying the Appointments table for Appointments with a doctor
    pending_appointments =  Appointments.query.filter(Appointments.DoctorID == None).all()
    # Gets pending appointments by querying the Appointments table for Appointments without a doctor
    return booked_appointments, pending_appointments


def get_appointments_doctor_info():
    all_booked_appointments, all_pending_appointments = get_appointments()

    pending_appointments = check_appointment_general_practice(all_pending_appointments)
    # Gets pending appointments that belong to the same GP as the user
    booked_appointments = check_appointment_general_practice(all_booked_appointments)
    # Gets booked appointments that belong to the same GP as the user
    
    doctor_info = []

    for appointment in booked_appointments:
        # Iterates through the booked_appointments list
        doctor = Users.query.filter_by(UserID=appointment.DoctorID).first()
        # Queries the User table for the users where the UserID is the same as the DoctorID mapped to the appointment
        doctor_info.append([doctor.Surname,doctor.Title])
        # Adds the doctor's surname and title to doctor_info
        
    return pending_appointments, booked_appointments, doctor_info

def get_appointments_patient_info():
    all_booked_appointments, all_pending_appointments = get_appointments()

    pending_appointments = check_appointment_general_practice(all_pending_appointments)
    # Gets pending appointments that belong to the same GP as the user
    booked_appointments = check_appointment_general_practice(all_booked_appointments)
    # Gets booked appointments that belong to the same GP as the user

    patient_info = []
    for appointment in booked_appointments:
        # Iterates through the booked_appointments list
        patient = Users.query.filter_by(UserID=appointment.PatientID).first()
        patient_info.append((patient.Surname,patient.Title))
        # Adds the patient surname and title as a tuple
    return pending_appointments, booked_appointments, patient_info

def check_appointment_general_practice(all_appointments):
    appointment_list = []
    user_id = get_current_id()
    # Gets the current user's ID
    user = Users.query.filter(Users.UserID == user_id).first()
    # Retrieves the user record from the User's table where the UserID matches user_id

    for appointment in all_appointments:
        # Loops throught the appointments passed through the parameter
        patient = Users.query.filter(Users.UserID == appointment.PatientID).first()
        # Retrieves the patient belonging to an appointment from the Users table where the UserID matches the appointment's PatientID
        if patient.General_Practice == user.General_Practice:
            # Checks if the appointment's patient belongs to the same general practice as the user
            appointment_list.append(appointment)
            # Adds the appointment to the list of appointments
    return appointment_list
    

def get_study_data(study_topic):
    ids = []
    studies = []
    
    response = requests.get(f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term=science[journal]+AND+{study_topic}")
    # Sends request to API, querying the study topic to get the ID's of studies that match the query
    response_xml_as_string = response.content
    # Turns the response into a string
    response_xml = ET.fromstring(response_xml_as_string)
    # Instantiates the xml element tree using the response string
    id_list_tag = response_xml.find('IdList')
    # Searches the tree object for the IdList tag 
   
    for id in id_list_tag:
        ids.append(id.text)
        # Iterates throught the IDs, appending them to a list of IDs

    for id in ids:
        response = requests.get(f"https://www.ncbi.nlm.nih.gov/pmc/utils/idconv/v1.0?tool=my_tool&email=amirhassanali2610@gmail.com.com&ids={id}")
        # Sends a request to an API that converts the ID into a PMCID 
        response_xml_as_string = response.content
        # Turns the response into a string
        response_xml = ET.fromstring(response_xml_as_string)
        # Instantiates the xml element tree using the response string
        time.sleep(1)
        # Sleeps for 1 second to prevent sending too many requests too quickly to the server
        try:
            pmcid = response_xml[1].attrib['pmcid']
            # Tries to find the pmcid tag that maps to the ID
            response = requests.get(f"https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/{pmcid}/unicode").json()
            # Sends requests to the API using the pmcid to retrieve the studies content in a json format
            studies.append([response['documents'][0]['passages'], pmcid])
            # appends the passages to the study
        except:
            pass

    return studies
    # returns the studies

def validate_user_conversation(user_id, conversation_id):
    conversation = Conversations.query.filter_by(ConversationID=conversation_id).first()
    # Retrieves the first conversation record in the conversation table where the ID matches the parameter
    if conversation != None:
        if (user_id == conversation.PatientID or user_id == conversation.DoctorID) and conversation.Status != 'Pending':
            # If the userID is either the patient's ID or the doctor's ID then return true
            return True
        else:
            return False

def validate_user_viewing_records(patient_id):
    # Converts the patient ID into an integer datatype
    user_id = get_current_id()
    # Gets the current user's ID
    role = get_user_role(user_id)
    # Gets user's role
    appointments = Appointments.query.filter_by(DoctorID=user_id).filter_by(PatientID=patient_id).filter(Appointments.Start_Date < datetime.now()).first()
    # Gets the first appointment where the Doctor ID is the same as user_id and the PatientID is the same as patient_id and the start date was before the date now
    # This makes sure that if the user accessing the page is a doctor, they have atleast one former appointment with the patient
    if (patient_id == user_id and role.Role_Name != 'Doctor')  or appointments != None:
        # Checks that there is atleast one appointment or that the patient's ID matches that of the user ID preventing other users accessing each other prescriptions and referrals
        return True
    else:
        return False

def get_sender_accounts(messages):
    sender_accounts = []

    for message in messages:
        sender = Users.query.filter(Users.UserID == message.SenderID).first()
        sender_accounts.append(sender)
        # Iterates through each message in the list of messages and retrieves the user whos userID matches the message's SenderID
    
    return sender_accounts

### End of functions


### Decorators

def role_required(role_names):
    # Takes role name as a parameter
    def outer_wrap(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            try:
                user_id = get_current_id()
                role = get_user_role(user_id)
                # Tries the get the user's role via their ID
                if role.Role_Name in role_names:
                    # If the role's name is the same as the role required, it runs the function
                    return f(*args, **kwargs)
                else:
                    abort(401)
            except:
                abort(401)
            # Otherwise it produces the error 401 screen
        return wrap
    return outer_wrap


### End of decorators



### Views

@app.context_processor
# Uses a context processor to inject variables into a templates context so that all templates are rendered with this variable
def inject_role():

    try:
        user_id = get_current_id()
        role = get_user_role(user_id) 
        # attemps to get the user ID and role  

    except:
        role = None
        # If the user ID or role can't be obtained the role is set to none

    return dict(role=role)


@app.errorhandler(401)
def access_denied(e):
    # Renders the 404.html if a 404 error is encountered
    return render_template('401.html'), 401

@app.errorhandler(404)
def page_not_found(e):
    # Renders the 404.html if a 404 error is encountered
    return render_template('404.html'), 404

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST','GET'])
def login():
    login_form = LoginForm()
    # Instantiates LoginForm

    if login_form.validate_on_submit():
        user = Users.query.filter_by(Email=login_form.Email.data).first()
        # If the login_form is valid it queries for the 'Users' table where the email is the same as the email posted
        if user:
            if login_form.check_password(user):
                login_user(user, remember=True)
                return redirect(url_for('index'))
                # If the user exists and the hashed password matches the password for that user in the database, the user is logged in and redirected to the index page
            else:
                flash("Incorrect password", category='Error')
                # Returns an "Incorrect password" flash message to the jinja which can then be rendered
        else:
            flash(f"{login_form.Email.data} isn't registered", category='Error')
            # Returns a flash message saying that the email hasn't been registered to the jinja which can then be rendered

    return render_template('login.html',login_form=login_form)
    # If the method is a GET method, the login page is rendered



@app.route('/register', methods=['POST','GET'])
def register():
    register_form = RegisterForm()
    # Instantiates RegisterForm
    if register_form.validate_on_submit() and register_form.validate_fields():
        # If the register_form is valid and the email hasn't already been used
            input_data = register_form.get_register_form_data()
            # All data from the from is retrieved from the POST method
            new_User = Users(Email=input_data['Email'], Password=input_data['Password'], Gender=input_data['Gender'], First_Name=input_data['First_Name'], Surname=input_data['Surname'], Contact_Number=input_data['Contact_Number'], Title=input_data['Title'], Date_Of_Birth=input_data['Date_Of_Birth'], Postcode=input_data['Postcode'], Address=input_data['Address'], General_Practice=input_data['General_Practice'])
            # Instantiates a new user
            new_User.add_role(input_data['Account_Type'])
            # Adds the user's role to the user
            add_to_database(new_User)
            # A User object is instantiated with the data retrieved before being added and commited to the database
            return redirect(url_for('login'))
            # The user is redirected to the login screen
            

    return render_template('register.html', register_form=register_form)
    # If the method is a GET request, the register page is rendered and register_form is passed on to the jinja 2



@app.route("/logout")
@login_required
# login_required decorator, requires a user logged in for the function to work
def logout():
    logout_user()
    return redirect(url_for('index'))
    # Once logged out, the user is redirected to the index page


@app.route("/research", methods=['POST', 'GET'])
def research():
    # Attempts to get the condition encoded in the url
    condition = request.args.get('condition')
    treatment = request.args.get('treatment')
    # Instantiates the forms
    condition_form = ConditionForm()
    treatment_form = TreatmentForm()

    if condition_form.validate_on_submit():
        condition = condition_form.Condition_Name.data
        corrected_condition = autocorrect(condition)
        # Auto corrects the condition

        if corrected_condition == condition:
            corrected_condition = None
            # If the autocorrected condition is the same as the condition entered, it is set to None as the condition hasn't been corrected

        primary_names, consumer_names, condition_links = get_condition_info(condition)
        # Gets the primary name, consumer name and link for each condition

        return render_template('research.html', treatment_form=treatment_form, condition_form=condition_form, primary_names=primary_names, consumer_names=consumer_names, condition_links=condition_links, corrected_condition=corrected_condition, first_treatment_visit = True)
    
    elif condition !=None and treatment_form.validate_on_submit() == False:
        corrected_condition = autocorrect(condition)
        # Auto corrects the condition

        if corrected_condition == condition:
            corrected_condition = None
             # If the autocorrected condition is the same as the condition entered, it is set to None as the condition hasn't been corrected

        primary_names, consumer_names, condition_links = get_condition_info(condition)
        # Gets the primary name, consumer name and link for each condition

        return render_template('research.html', treatment_form=treatment_form, condition_form=condition_form, primary_names=primary_names, consumer_names=consumer_names, condition_links=condition_links, corrected_condition=corrected_condition, first_treatment_visit = True)

    if treatment_form.validate_on_submit():
        treatment = treatment_form.Treatment_Name.data
        corrected_treatment = autocorrect(treatment)
        # Auto corrects the treatment
        
        if corrected_treatment == treatment:
            corrected_treatment = None
            # If the autocorrected treatment is the same as the treatment entered, it is set to None as the treatment hasn't been corrected
        
        treatment_data = get_treatment_info(treatment)
        # Gets the treatment_data for the treatment

        return render_template('research.html', treatment_form=treatment_form, condition_form=condition_form, treatment_data = treatment_data, corrected_treatment = corrected_treatment, first_condition_visit = True)
    
    elif treatment != None and condition_form.validate_on_submit() == False:

        corrected_treatment = autocorrect(treatment)
        # Auto corrects the treatment

        if corrected_treatment == treatment:
            corrected_treatment = None
            # If the autocorrected treatment is the same as the treatment entered, it is set to None as the treatment hasn't been corrected

        treatment_data = get_treatment_info(treatment)
        # Gets the treatment_data for the treatment

        return render_template('research.html', treatment_form=treatment_form, condition_form=condition_form, treatment_data = treatment_data, corrected_treatment = corrected_treatment, first_condition_visit = True)
        
        
    return render_template('research.html', treatment_form=treatment_form, condition_form=condition_form, first_treatment_visit=True, first_condition_visit = True)


@app.route("/booking", methods=['POST', 'GET'])
@role_required(role_names=('Patient'))
def booking():
    pending_appointments, booked_appointments, doctor_info = get_appointments_doctor_info()
    # Gets the pending appointments, booked appointments and doctor info from the 'get_appointments_doctor_info' function
    return render_template('booking.html', pending_appointments=pending_appointments, booked_appointments=booked_appointments, doctor_info=doctor_info)
    

@app.route("/add_appointment", methods=['POST']) 
@role_required(role_names=('Patient'))
def add_appointment():
    if request.method == 'POST':
        date = request.form['date'].split(" (",1)[0]
        # Splits the date so that it doesn't include the information in the brackets
        user_id = get_current_id()
        start_date = datetime.strptime(date, '%a %b %d %Y %H:%M:%S %Z%z')
        # Parses the date as weekday, month, day of the month, year then hour:minute:second then UTC Offset and Timezone
        end_date = start_date + timedelta(days=1)
        # Adds 1 day to the date to get the maximum end date
        new_appointment = Appointments(PatientID=user_id, Start_Date=start_date, End_Date=end_date)
        # Instantiates a new appointment
        add_to_database(new_appointment)
        # Adds the appointment to the database
        return redirect(url_for('booking'))
    
@app.route("/delete_appointment", methods=['POST']) 
@role_required(role_names=('Patient', 'Doctor'))
def delete_appointment():
    if request.method == 'POST':
        appointment_id = request.form['appointment_id']
        Appointments.query.filter_by(AppointmentID=appointment_id).delete()
        # Deletes the appointment where the AppointmentID matches the ID that was posted
        db.session.commit()
        # Commits the changes to the database
        user_id = get_current_id()
        role = get_user_role(user_id)
        if role.Role_Name == 'Doctor':
            return redirect(url_for('view_appointments'))
        else:
            return redirect(url_for('booking'))

@app.route("/appointments") 
@role_required(role_names=('Doctor'))
def view_appointments():
    pending_appointments, booked_appointments, patient_info = get_appointments_patient_info()
    # Gets the pending appointments, booked appointments and patient info from the 'get_appointments_patient_info' function
    return render_template('appointments.html', pending_appointments=pending_appointments, booked_appointments=booked_appointments, patient_info = patient_info)

@app.route("/take_appointment", methods=['POST']) 
@role_required(role_names=('Doctor'))
def take_appointment():
    if request.method == 'POST':
        appointment_id = request.form['appointment_id']
        appointment =  Appointments.query.filter_by(AppointmentID=appointment_id).first()
        # Queries the Appointments table for the appointment where the AppointmentID matches the ID from the POST
        appointment.DoctorID = get_current_id()
        # Changes the Appointments DoctorID to the user ID
        db.session.commit()
        # Commits changes
        return redirect(url_for('view_appointments'))
    
@app.route("/update_appointment", methods=['POST']) 
@role_required(role_names=('Doctor'))
def update_appointment():
    if request.method == 'POST':

        appointment_id = request.form['appointment_id']
        start_date = request.form['start_date'].split(" (",1)[0]
        end_date = request.form['end_date'].split(" (",1)[0]    
        # Retrieves the AppointmentID, start date and end date

        start_datetime = datetime.strptime(start_date, '%a %b %d %Y %H:%M:%S %Z%z')
        end_datetime = datetime.strptime(end_date, '%a %b %d %Y %H:%M:%S %Z%z')
        # Parses the dates as weekday, month, day of the month, year then hour:minute:second then UTC Offset and Timezone

        appointment = Appointments.query.filter_by(AppointmentID=appointment_id).first()
        # Queries the Appointments table for the appointment where the AppointmentID matches the ID from the POST
        appointment.Start_Date = start_datetime
        # Modifies the appointments Start_Date to start_datetime
        appointment.End_Date = end_datetime
        # Modifies the appointments end_Date to end_datetime
        db.session.commit()
        # Commits the changes
        return redirect(url_for('view_appointments'))
    
@app.route("/studies", methods=['GET','POST']) 
def studies():
    study_topic = request.args.get('study')
    pmcid = request.args.get('pmcid')
    # Gets the study topic and pmcid from the URL
    studies_form = StudiesForm()

    if studies_form.validate_on_submit():
        study_topic = studies_form.Study_Topic.data
        corrected_study = autocorrect(study_topic)
        # If the form is valid and has been submitted, retrieves the study and autocorrects it 

        if corrected_study == study_topic:
            corrected_study = None
        # If the autocorrected study is the same as the study entered, it is set to None as the study hasn't been corrected

        studies = get_study_data(study_topic)
        # studies is the data returned by the get_study_data function
        return render_template('studies.html', corrected_study = corrected_study, studies_form = studies_form, studies=studies)

    elif study_topic !=None:
        corrected_study = autocorrect(study_topic)
        # If there is a study topic retrieved from the url, it autocorrects the study
        if corrected_study == study_topic:
            corrected_study = None
            # If the corrected study is the same as the study topic from the url, it is set to None as the study has not been auto-corrected.

        studies = get_study_data(study_topic)
         # studies is the data returned by the get_study_data function
        return render_template('studies.html', corrected_study = corrected_study, studies_form = studies_form, studies=studies)

    elif pmcid != None:
        try:
            response = requests.get(f"https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/{pmcid}/unicode").json()
            # If there is a pmcid in the url, it gets the data associated with the pmcid
            study_content = response['documents'][0]['passages']
            # It gets the passages from the json response 
            return render_template('study.html',study_content=study_content)
        except:
            abort(404)

    return render_template('studies.html',studies_form = studies_form, first_visit=True)

@app.route("/patient_conversations", methods=['GET']) 
@login_required
@role_required(role_names=('Patient'))
def view_patient_conversations():
    user_id = get_current_id()
    inactive_conversations = Conversations.query.filter(Conversations.PatientID == user_id).filter(Conversations.Status == 'Inactive').order_by(Conversations.ConversationID.desc()).all()
    # Retrieves all inactive conversations that belong to the patient by finding conversations where the user's ID matches the current user's ID and the status is 'Inactive' and orders them by ConversationID descending so that the most recent conversations appear first
    pending_conversation = Conversations.query.filter(Conversations.PatientID == user_id).filter(Conversations.Status == 'Pending').first()
    # Retrieves the first pending conversation that belongs to the patient by finding conversations where the user's ID matches the current user's ID and the status is 'Pending'
    active_conversation = Conversations.query.filter(Conversations.PatientID == user_id).filter(Conversations.Status == 'Active').first()
    # Retrieves the first active conversation that belongs to the patient by finding conversations where the user's ID matches the current user's ID and the status is 'Active'

    return render_template('patient_conversations.html', inactive_conversations=inactive_conversations, pending_conversation=pending_conversation, active_conversation=active_conversation)

@app.route("/create_conversation", methods=['POST']) 
@login_required
@role_required(role_names=('Patient'))
def create_conversation():
    if request.method == 'POST':
        user_id = get_current_id()
        # Gets the current user's ID
        new_converstaion = Conversations(PatientID=user_id, Status='Pending')
        add_to_database(new_converstaion)
        # Creates a conversation with the Pending status and saves and commits it to the database
        return redirect(url_for('view_patient_conversations'))

@app.route("/doctor_conversations") 
@role_required(role_names=('Doctor'))
@login_required
def view_doctor_conversations():
    user_id = get_current_id()
    # Gets the current user's ID
    inactive_conversations = Conversations.query.filter(Conversations.DoctorID == user_id).filter(Conversations.Status == 'Inactive').order_by(Conversations.ConversationID.desc()).all()
    # Retrieves all inactive conversations that belong to the doctor by finding conversations where the user's ID matches the current user's ID and the status is 'Inactive' and orders them by ConversationID descending so that the most recent conversations appear first
    active_conversations = Conversations.query.filter(Conversations.DoctorID == user_id).filter(Conversations.Status == 'Active').order_by(Conversations.ConversationID.desc()).all()
    # Retrieves all active conversations that belong to the doctor by finding conversations where the user's ID matches the current user's ID and the status is 'Inactive' and orders them by ConversationID descending so that the most recent conversations appear first
    pending_conversations= Conversations.query.filter(Conversations.Status == 'Pending').all()
    # Retrieves all pending conversations that belong to the doctor by finding conversations where the user's ID matches the current user's ID and the status is 'Inactive' 
    if (not inactive_conversations and not active_conversations) and not pending_conversations:
        # Checks if the inactive_conversations, active_conversations and pending_conversations are empty
        no_conversations = True
    else:
        no_conversations = None
    return render_template('doctor_conversations.html', active_conversations=active_conversations, pending_conversations=pending_conversations, inactive_conversations=inactive_conversations, no_conversations=no_conversations)

@app.route("/take_conversation", methods=['POST']) 
@login_required
@role_required(role_names=('Doctor'))
def take_conversation():
    if request.method == 'POST':
        user_id = get_current_id()
        # Gets the current user's ID
        conversation_id = request.form['conversation_id']
        # Gets the conversation ID from the POST
        conversation= Conversations.query.filter(Conversations.ConversationID == conversation_id).first()
        # Rerieves the first conversation from the Conversation's table where ConversationID is the same as conversation_id
        conversation.DoctorID = user_id
        # Changes the conversation's DoctorID to the current user's ID
        conversation.Status = 'Active'
        # Changes the conversation's status to 'Active'
        db.session.commit()
        # Commits the changes to the database
        return redirect(url_for('view_doctor_conversations'))

@app.route("/end_conversation", methods=['POST']) 
@login_required
@role_required(role_names=('Doctor'))
def end_conversation():
    if request.method == 'POST':
        conversation_id = request.form['conversation_id']
        # Retrieves the conversation ID from the POST
        conversation = Conversations.query.filter(Conversations.ConversationID == conversation_id).first()
        # Retreives the first onversation where the conversation_id matches the Conversation's ID
        conversation.Status = 'Inactive'
        # Sets the conversation's status to 'Inactive'
        db.session.commit()
        # Commits changes to the database
        return redirect(url_for('view_doctor_conversations'))

@app.route("/view_conversation/<conversation_id>", methods=['GET', 'POST']) 
# Takes a dynamic URL where the path contains the conversation ID
@login_required
@role_required(role_names=('Doctor', 'Patient'))
def view_conversation(conversation_id):
    user_id = get_current_id()
    # Retrieves the user's ID
    if validate_user_conversation(user_id, conversation_id):
        # Checks that the user can view the conversation
        message_form = MessageForm()
        # Instantiates a message form
        conversation = Conversations.query.filter(Conversations.ConversationID == conversation_id).first()
        # Retrieves the conversation from the Conversations table where conversation_id matches the Conversations ID

        if message_form.validate_on_submit():
            contents = message_form.Contents.data
            # If the form is valid and has been submitted, sets the contents to the form's Contents
            date = datetime.now()
            # Sets the date as the current date
            if conversation.Status != 'Inactive':
                new_message = Messages(SenderID=user_id, ConversationID=conversation_id, Content=contents, Date=date)
                # If the conversation's status isn't 'Inactive', creates a new message
                add_to_database(new_message)
                # Adds the new message to the database
            return redirect('/view_conversation/'+conversation_id)
            # returns a redirect to the same conversation's page
        

        messages = Messages.query.filter(Messages.ConversationID == conversation_id).all() 
        # Retrieves all messages from the Message table where the message's conversation ID matches conversation_id
        sender_accounts = get_sender_accounts(messages)
        # Retrieves all the sender_account for each message using the get_sender_accounts function
            
        return render_template('message.html', messages=messages, sender_accounts=sender_accounts, message_form=message_form, conversation=conversation)
    abort(401)


@app.route("/delete_message", methods=['POST']) 
@login_required
@role_required(role_names=('Doctor', 'Patient'))
def delete_message():
    if request.method == 'POST':
        message_id = request.form['message_id']
        # Gets the message ID from the POST
        conversation_id = request.form['conversation_id']
        # Gets the conversation ID from the POST
        Messages.query.filter_by(MessageID=message_id).delete()
        # Deletes the message in the Message table where the message ID matches message_id
        db.session.commit()
        # Commits changes
        return redirect('/view_conversation/'+conversation_id)

@app.route("/prescriptions_referrals_doctors", methods=['GET', 'POST']) 
@login_required
@role_required(role_names=('Doctor'))
def prescriptions_referrals_doctors():
    doctor_id = get_current_id()
    # Gets the current user's ID as that is the doctor's ID
    former_appointments = Appointments.query.filter(Appointments.DoctorID == doctor_id).filter(Appointments.Start_Date < datetime.now()).all()
    # Gets the all of the doctor's former appointments by querying the Appointments table for appointments where the DoctorID matches doctor_id and filters them where there start date is before now, meaning the appointment has already started
    patients = []
    referral_form = ReferralForm()
    # Instantiates a referral form
    prescription_form = PrescriptionForm()
    # Instantiates a prescription form


    for appointment in former_appointments:
        # Iterates through the former appointments
        patient = Users.query.filter_by(UserID = appointment.PatientID).first()
        # Retrieves the patient by querying the User table for first user where the UserID is the same as the appointment's patient ID
        if not patient in patients:
            # To avoid patients being displayed multiple times if they had former appointments, only patients that haven't been added are added to the list
            patients.append(patient)
        

    if prescription_form.validate_on_submit():
        # If the presecription form is valid and has been submitted
        dosage = prescription_form.Dosage.data
        frequency = prescription_form.Frequency.data
        treatment = prescription_form.Treatment.data
        patient_id = prescription_form.PatientID.data
        # Gets the prescription form's data 

        date = datetime.now()
        # Sets the date to the time right now
        new_prescription = Prescriptions(PatientID=patient_id, DoctorID=doctor_id, Date=date, Treatment=treatment, Dosage=dosage, Frequency=frequency)
        # Creates a prescription
        add_to_database(new_prescription)
        # Adds the prescription to the database


    elif referral_form.validate_on_submit():
        # If the referral form is valid and has been submitted
        details = referral_form.Details.data
        description = referral_form.Description.data
        patient_id = referral_form.Patientid.data
        # Gets the referral form's data

        date = datetime.now()
        # Sets the date to the time right now
        new_referral = Referrals(PatientID=patient_id, DoctorID=doctor_id, Date=date, Details=details, Description=description)
        # Creates a referal
        add_to_database(new_referral)
        # Adds the referral to the database

    return render_template("prescriptions_referrals_doctors.html", patients=patients, referral_form=referral_form, prescription_form=prescription_form)
    
@app.route("/view_records/<patient_id>", methods=['GET', 'POST'])
# Takes a dynamic URL where the path contains the patient ID 
@role_required(role_names=('Doctor', 'Patient'))
@login_required
def view_records(patient_id):
    patient_id = int(patient_id)
    if validate_user_viewing_records(patient_id): 
        referrals = Referrals.query.filter_by(PatientID=patient_id).order_by(Referrals.Date.desc()).all()
        # Retrieves all referrals from the Referrals table where the PatientID matches the patient_id and orders them by date descending so that the newest referrals appear first
        prescriptions = Prescriptions.query.filter_by(PatientID=patient_id).order_by(Prescriptions.Date.desc()).all()
        # Retrieves all prescriptions from the Prescriptions table where the PatientID matches the patient_id and orders them by date descending so that the newest prescriptions appear first
        return render_template("view_records1.html", referrals=referrals, prescriptions=prescriptions, patient_id=patient_id)
    
    else:
        abort(404)

if __name__=='__main__':
    app.run(host="0.0.0.0", debug=True)
