from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import flask_login
import os
import enum

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(80), unique=True, nullable=False)

    def __init__(self, category_name):
        self.category_name = category_name


class CategorySchema(ma.Schema):
    class Meta:
        fields = ('id', 'category_name')


category_schema = CategorySchema()
categories_schema = CategorySchema(many=True)


class ReportReason(enum.Enum):
    BAD_LANGUAGE = 'Contains offensive language'
    SCAM = 'Is trying to scam somebody'


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_reason = db.Column(db.Integer, db.Enum(ReportReason), nullable=False)
    advertisement = db.Column(db.Integer, db.ForeignKey('advertisement.id'), nullable=False)
    reporter = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class ReportSchema(ma.Schema):
    class Meta:
        fields = ('id', 'report_reason', 'advertisement', 'reporter')


report_schema = ReportSchema()
reports_schema = ReportSchema(many=True)


class EndReason(enum.Enum):
    SOLD = "Sold"
    NOT_SOLD = "Not sold"


class Advertisement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    price = db.Column(db.Float(precision='5,2'))
    is_promoted = db.Column(db.Boolean(), nullable=False)
    photo_path = db.Column(db.String(500))
    category = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    end_reason = db.Column(db.Integer, db.Enum(EndReason), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    phone_number = db.Column(db.Integer, unique=True, nullable=False)
    show_phone = db.Column(db.Boolean, nullable=False)
    password_hash = db.Column(db.String(128))
    is_activated = db.Column(db.Boolean(), default=False)
    is_admin = db.Column(db.Boolean(), default=False)
    is_moderator = db.Column(db.Boolean(), default=False)
    delete_date = db.Column(db.DateTime())

    def __init__(self, name, email, phone, show):
        self.name = name
        self.email = email
        self.phone_number = phone
        self.show_phone = show


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'phone_number')


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class UserDetailsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'phone_number', 'delete_date', 'email', 'is_admin', 'is_moderator', 'show_phone')


user_details_schema = UserDetailsSchema()
users_details_schema = UserDetailsSchema(many=True)


@app.route('/api/user', methods=['POST'])
def create_user():
    name = request.json['name']
    email = request.json['email']
    phone = request.json['phone']
    show_phone = request.json['show_phone']
    new_user = User(name, email, phone, show_phone)

    db.session.add(new_user)
    db.session.commit()

    return user_details_schema.jsonify(new_user)


@app.route('/api/user', methods=['GET'])
def get_users():
    all_users = User.query.all()
    result = users_details_schema.dump(all_users)
    return jsonify(result)


@app.route('/api/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)

    return user_details_schema.jsonify(user)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.Integer, db.ForeignKey('advertisement.id'), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    person_a = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    person_b = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_text = db.Column(db.String(500), nullable=False)
    message_date = db.Column(db.DateTime, nullable=False)
    direction = db.Column(db.Boolean(), nullable=False)
    conversation = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)


class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), nullable=False)
    value = db.Column(db.String(80), nullable=False)


@app.route('/')
def index():
    return 'Wale wiadro'


@app.route('/api/ad/<id>/report', methods=['POST'])
def create_report(id):
    report_reason = request.json['reason']
    new_report = Report(report_reason, id, flask_login.current_user.get_id())

    db.session.add(new_report)
    db.session.commit()

    return report_schema.jsonify(new_report)

@app.route('/api/report/<id>', methods=['GET'])
def get_report(id):
    report = Report.query.get(id)
    return report_schema.jsonify(report)

@app.route('/api/report/<id>', methods=['DELETE'])
def delete_report(id):
    report = Report.query.get(id)
    db.session.delete(report)
    db.session.commit()
    return report_schema.jsonify(report)

@app.route('/api/mod/reports', methods=['GET'])
def get_reports():
    all_reports = Report.query.all()
    result = reports_schema.dump(all_reports)
    return jsonify(result)


@app.route('/api/mod/reports/<id>', methods=['POST'])
def review_report(id):
    is_ok = request.json["isOk"]
    ban_user = request.json["banUser"]
    
    if is_ok:
        delete_report(id)

    if ban_user:
        report = get_report(id)
        advertisment = get_advetisement(report.advertisement)
        user = advertisment.owner
        delete_user(user)

@app.route('/api/category', methods=['POST'])
def create_category():
    name = request.json['category_name']
    new_category = Category(name)

    db.session.add(new_category)
    db.session.commit()

    return category_schema.jsonify(new_category)


@app.route('/api/category', methods=['GET'])
def get_categories():
    all_categories = Category.query.all()
    result = categories_schema.dump(all_categories)
    return jsonify(result)


@app.route('/api/category/<id>', methods=['GET'])
def get_category(id):
    category = Category.query.get(id)

    return category_schema.jsonify(category)


@app.route('/api/category/<id>', methods=['PUT'])
def update_category(id):
    category = Category.query.get(id)
    category.category_name = request.json['category_name']

    db.session.commit()
    return category_schema.jsonify(category)


@app.route('/api/category/<id>', methods=['DELETE'])
def delete_category(id):
    category = Category.query.get(id)
    db.session.delete(category)
    db.session.commit()
    return category_schema.jsonify(category)


if __name__ == '__main__':
    db.create_all()
    app.run(port=8000, debug=True, host='0.0.0.0')
