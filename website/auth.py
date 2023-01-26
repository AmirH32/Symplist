from flask import Blueprint, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length
from . import db
from .models import Patient
from .__init__ import bcrypt
from flask_login import login_user, logout_user, login_required

auth = Blueprint("auth", __name__)

# Uses wtforms to create a form that includes a CRSF_token
class RegisterForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    confirm_Password = PasswordField(label='Confirmed Password', validators=[InputRequired("Confirm your password"),Length(max=128)], render_kw = {"placeholder" : "Confirmed Password"})
    Submit = SubmitField("Register")

    # Validate_email method raises an error if the email already exists in the database

    def validate_email(self, email):
        existing_email = Patient.query.filter_by(Email=email.data).first()

        if existing_email:
            flash("User with that email already exists.", category='error')
            return False

        return True


class LoginForm(FlaskForm):
    Email = EmailField(label='Email', validators=[InputRequired("Enter your email address."), Length(max=256)], render_kw = {"placeholder" : "Email"})
    Password = PasswordField(label='Password', validators=[InputRequired("Enter your password"),Length(max=128)], render_kw = {"placeholder" : "Password"})
    Submit = SubmitField("Login")

@auth.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        patient = Patient.query.filter_by(Email=form.Email.data).first()
        if patient:
            print(form.Password.data)
            if bcrypt.check_password_hash(patient.Password, form.Password.data):
                login_user(Patient, remember=True)
                return redirect(url_for('views.index'))
            else:
                flash("Incorrect password", category='error')
        else:
            flash("That email doesn't exist", category='error')
    return render_template('login.html',form=form)

@auth.route('/register', methods=['POST','GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit() and form.validate_email(email=form.Email):
        pass1 = form.Password.data
        confirm_pass1 = form.confirm_Password.data
        if pass1 == confirm_pass1:
            hashed_password = bcrypt.generate_password_hash(form.Password.data)
            new_Patient = Patient(Email=form.Email.data, Password=hashed_password)
            db.session.add(new_Patient)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            flash("Password and confirmed password are not the same.")

    return render_template('register.html', form=form)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("views.index"))
