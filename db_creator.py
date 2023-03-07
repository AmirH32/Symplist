from Symplist import app, db, Roles

app.app_context().push()
db.create_all() 

doctor = Roles(Role_Name="Doctor")
patient = Roles(Role_Name="Patient")
db.session.add(doctor)
db.session.add(patient)
db.session.commit()
