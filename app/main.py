from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)
class Category(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    category_name = db.Column(db.String(80), unique = True, nullable = False)
    advertisements = db.relationship("Advertisement", backref="category", lazy=True)

    def __repr__(self):
        return self.category_name

class TerminationReason(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    termination_reason = db.Column(db.String(80), unique = True, nullable = False)
    advertisements = db.relationship("Advertisement", backref="reason", lazy=True)


    def __repr__(self):
        return self.termination_reason

class ReportReason(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    report_reason = db.Column(db.String(80), unique = True, nullable = False)
    reports = db.relationship("Report", backref = "reason", lazy = True)

    def __repr__(self):
        return self.report_reason

class Report(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    report_reason = db.Column(db.Integer, db.ForeignKey('report_reason.id') , nullable =  False)
    advertisement = db.Column(db.Integer, db.ForeignKey('advertisement.id') , nullable =  False)
    reporter = db.Column(db.Integer, db.ForeignKey('user.id') , nullable =  False)

    #TODO: discuss what string should represt report
    def __repr__(self):
        return self.report_reason

class Advertisement(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(80),nullable = False)
    description = db.Column(db.String(500),nullable = False)
    price = db.Column(db.Float (precision='5,2'))
    photo_path = db.Column(db.String(500))
    category = db.Column(db.Integer, db.ForeignKey('category.id') , nullable =  False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id') , nullable =  False)
    termination_reason = db.Column(db.Integer, db.ForeignKey('termination_reason.id') , nullable =  False)



    def __repr__(self):
        return self.title

class User(db.Model):

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(80),nullable = False)
    surname = db.Column(db.String(80),nullable = False)
    email = db.Column(db.String(80), unique = True, nullable = False)
    phone_number = db.Column(db.Integer, unique = True, nullable = False)
    password_hash = db.Column(db.String(128))
    is_activated = db.Column(db.Boolean(),default = False)
    is_admin = db.Column(db.Boolean(),default = False)
    is_moderator = db.Column(db.Boolean(),default = False)
    to_dlete = db.Column(db.Boolean(),default = False)
    delete_date= db.Column(db.DateTime())
    advertisements = db.relationship("Advertisement", backref="owner", lazy=True)
    messages_send = db.relationship("Message", backref="sender", lazy=True)
    messages_received = db.relationship("Message", backref="receiver", lazy=True)

    def __repr__(self):
        return self.name + " " + self.surname

class Message(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    message_text = db.Column(db.String(500),nullable = False)
    sender = db.Column(db.Integer, db.ForeignKey('user.id') , nullable =  False)
    receiver = db.Column(db.Integer, db.ForeignKey('user.id') , nullable =  False)
    advertisement = db.Column(db.Integer, db.ForeignKey('advertisement.id') , nullable =  False)

class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    key = db.Column(db.String(80),nullable = False)
    value = db.Column(db.String(80),nullable = False)


@app.route('/')
def index():
    return 'Wale wiadro'

if __name__ == '__main__':
    app.run(port=8000,debug=True, host='0.0.0.0')