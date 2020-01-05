from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from passlib.apps import custom_app_context as pwd_context
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_mail import Mail, Message
from functools import wraps
import os
import enum
import datetime
import jwt

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['SECRET_KEY'] = 'jwt-secret-string'
app.config['MAIL_SERVER'] = 'mail.cock.li'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'ogloszenioofka@nuke.africa'
app.config['MAIL_PASSWORD'] = 'MyciekTop'
jwtmgr = JWTManager(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
mail = Mail(app)


def require_permissions(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current = get_jwt_identity()
            user = User.find_by_email(current)
            if access_level is "admin":
                if not user.is_admin:
                    return "", 403
            if access_level is "mod":
                if not user.is_moderator and not user.is_admin:
                    return "", 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def is_owner():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current = get_jwt_identity()
            user = User.find_by_email(current)

            model_id = kwargs["id"]
            model = Advertisement.query.get(model_id)
            if not model.owner == user.email:
                return "", 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


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

    def __init__(self, report_reason, advertisement):
        self.report_reason = report_reason
        self.advertisement = advertisement


class ReportSchema(ma.Schema):
    class Meta:
        fields = ('id', 'report_reason', 'advertisement')


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
    end_reason = db.Column(db.Integer, db.Enum(EndReason), nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    expected_end_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)

    def __init__(self, price, title, category, photo_path, description, owner):
        self.price = price
        self.title = title
        self.category = category
        self.photo_path = photo_path
        self.description = description
        self.owner = owner
        self.start_date = datetime.datetime.now()
        self.is_promoted = False
        self.expected_end_date = self.start_date + datetime.timedelta(days=30)


class AdvertisementSchema(ma.Schema):
    class Meta:
        fields = ('id', 'price', 'start_date', 'end_date', 'end_reason', 'title', 'category', 'owner', 'photo_path',
                  'is_promoted')


advertisement_schema = AdvertisementSchema()
advertisements_schema = AdvertisementSchema(many=True)


class AdvertisementDetailsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'price', 'start_date', 'end_date', 'end_reason', 'title', 'category', 'owner', 'photo_path',
                  'is_promoted', 'description')


advertisement_details_schema = AdvertisementDetailsSchema()


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

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    @classmethod
    def find_by_email(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user is None:
            raise FileNotFoundError
        return user


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


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.Integer, db.ForeignKey('advertisement.id'), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, user, ad):
        self.user = user
        self.ad = ad


class FavoriteSchema(ma.Schema):
    class Meta:
        fields = ("id", "user", "ad")


favorite_schema = FavoriteSchema()
favorites_schema = FavoriteSchema(many=True)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    person_a = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    person_b = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, person_a, person_b):
        self.person_a = person_a
        self.person_b = person_b


class ConversationSchema(ma.Schema):
    class Meta:
        fields = ("id", "person_a", "person_b")


conversation_schema = ConversationSchema()
conversations_schema = ConversationSchema(many=True)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_text = db.Column(db.String(500), nullable=False)
    message_date = db.Column(db.DateTime, nullable=False)
    direction = db.Column(db.Boolean(), nullable=False)
    conversation = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    direction = db.Column(db.Boolean(), nullable=True)

    def __init__(self, message_text, direction, conversation):
        self.message_text = message_text
        self.direction = direction
        self.conversation = conversation
        self.message_date = datetime.datetime.now()


class MessageSchema(ma.Schema):
    class Meta:
        fields = ("id", "message_text", "message_date", "conversation", "direction")


message_schema = MessageSchema()
messages_schema = MessageSchema(many=True)


class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), nullable=False, unique=True)
    value = db.Column(db.String(80), nullable=False)

    def __init__(self, key, value):
        self.key = key
        self.value = value


class AppSettingsSchema(ma.Schema):
    class Meta:
        fields = ('key', 'value')


app_settings_schema = AppSettingsSchema(many=True)


@app.route('/')
def index():
    return 'Wale wiadro'


@app.route('/api/user', methods=['POST'])
def create_user():
    name = request.json['name']
    email = request.json['email']
    phone = request.json['phone']
    show_phone = request.json['showPhone']
    password = request.json['password']
    new_user = User(name, email, phone, show_phone)
    new_user.hash_password(password)
    # refresh_token = create_refresh_token(identity=email)

    db.session.add(new_user)
    db.session.commit()
    token = encode_auth_token(new_user.id)
    send_email(email, token)
    #
    # to_return = user_details_schema.jsonify(new_user)
    # to_return['access_token']=access_token
    # to_return['refresh_token']=refresh_token
    return user_details_schema.jsonify(new_user)


def encode_auth_token(id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': id,
        }
        token = str(jwt.encode(
            payload,
            app.config.get('JWT_SECRET_KEY'),
            algorithm='HS256'
        ))
        token = token.replace("'", '')
        token = token[1:]
        return token
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config.get('JWT_SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


@app.route('/api/activate/<token>/<email>', methods=['GET'])
def activate_user(token, email):
    try:
        user = User.find_by_email(email)
    except FileNotFoundError:
        return {'message': 'No such user'}

    id = decode_auth_token(token)
    if id is not user.id:
        return {'message': 'Wrong token'}

    user.is_activated = True

    db.session.commit()
    return user_details_schema.jsonify(user)


@app.route('/api/login', methods=['POST'])
def login():
    password = request.json['password']
    email = request.json['email']
    try:
        user = User.find_by_email(email)
    except FileNotFoundError:
        return {'message': 'No such user'}

    if not user.is_activated:
        return {'message': 'User not activated'}
    if user.verify_password(password):
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)
        return {
            'message': 'Logged in as {}'.format(user.email),
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    else:
        return {'message': 'Wrong credentials'}


@app.route('/api/me', methods=["GET"])
@jwt_required
def get_current_user():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    return user_details_schema.jsonify(user)


@app.route('/api/me', methods=["PUT"])
@jwt_required
def update_current_user():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    user.name = request.json["name"]
    user.email = request.json["email"]
    user.phone_number = request.json["phone"]
    user.show_phone = request.json["showPhone"]

    db.session.commit()
    return user_details_schema.jsonify(user)


@app.route('/api/me', methods=["DELETE"])
@jwt_required
def delete_current_user():
    current = get_jwt_identity()
    user = User.find_by_emai7l(current)
    user.delete_date = datetime.datetime.now() + datetime.timedelta(days=7)

    db.session.commit()

    return user_details_schema.jsonify(user)


@app.route('/api/me/cancel-delete', methods=["POST"])
@jwt_required
def cancel_delete():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    user.delete_date = None

    return user_details_schema.jsonify(user)


@app.route('/api/me/favorite', methods=["GET"])
@jwt_required
def get_favorite_ads():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    favorites = Favorite.query.filter_by(user=user.id)
    ads = []
    for favorite in favorites:
        ads.append(Advertisement.query.get(favorite.ad))

    return advertisements_schema.jsonify(ads)


@app.route('/api/me/ads', methods=["GET"])
@jwt_required
def get_my_ads():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    my_ads = Advertisement.query.filter_by(owner=user.email)

    return advertisements_schema.jsonify(my_ads)


@app.route('/api/ad', methods=['POST'])
@jwt_required
def create_advertisement():
    price = request.json['price']
    title = request.json['title']
    category = request.json['categoryId']
    photo_path = request.json['pictureUrl']
    description = request.json['description']
    owner = get_jwt_identity()

    new_advertisement = Advertisement(price, title, category, photo_path, description, owner)

    db.session.add(new_advertisement)
    db.session.commit()

    return advertisement_schema.jsonify(new_advertisement)


@app.route('/api/ad', methods=['GET'])
def get_advertisements():
    all_advertisement = Advertisement.query.all()
    result = advertisements_schema.dump(all_advertisement)
    # TODO
    # filtry wyszukiwania
    return jsonify(result)


@app.route('/api/ad/<id>', methods=['GET'])
@jwt_required
def get_advertisement(id):
    advertisement = Advertisement.query.get(id)
    # TODO
    # doklejenie informacji o tym czy jest w ulubionych
    return advertisement_details_schema.jsonify(advertisement)


@app.route('/api/ad/<id>', methods=['PUT'])
@jwt_required
@is_owner()
def update_advertisement(id):
    advertisement = Advertisement.query.get(id)
    advertisement.price = request.json['price']
    advertisement.title = request.json['title']
    advertisement.category = request.json['categoryId']
    advertisement.photo_path = request.json['pictureUrl']
    advertisement.description = request.json['description']

    db.session.commit()
    return advertisement_schema.jsonify(advertisement)


@app.route('/api/ad/<id>', methods=['DELETE'])
@jwt_required
@is_owner()
def delete_advertisement(id):
    advertisement = Advertisement.query.get(id)
    advertisement.end_date = datetime.datetime.now()
    advertisement.end_reason = request["reason"]

    db.session.commit()


@app.route('/api/ad/<id>/extend', methods=['POST'])
@jwt_required
@is_owner()
def extend_advertisement(id):
    advertisement = Advertisement.query.get(id)
    advertisement.expected_end_date = datetime.datetime.now() + datetime.timedelta(days=30)

    db.session.commit()
    return advertisement_schema.jsonify(advertisement)


@app.route('/api/ad/<id>/promote', methods=['POST'])
@jwt_required
@is_owner()
def promote_advertisement(id):
    advertisement = Advertisement.query.get(id)
    advertisement.is_promoted = True

    db.session.commit()
    return advertisement_schema.jsonify(advertisement)


@app.route('/api/ad/<id>/favorite', methods=['POST'])
@jwt_required
def add_ad_to_favorite(id):
    advertisement = Advertisement.query.get(id)
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    new_favorite = Favorite(user.id, id)

    db.session.add(new_favorite)
    db.session.commit()

    return advertisement_details_schema.jsonify(advertisement)


@app.route('/api/ad/<id>/favorite', methods=['DELETE'])
@jwt_required
def delete_ad_from_favorite(id):
    advertisement = Advertisement.query.get(id)
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    favorite = Favorite.query.filter_by(ad=id, user=user.id).first()

    db.session.delete(favorite)
    db.session.commit()

    return advertisement_details_schema.jsonify(advertisement)


@app.route('/api/ad/<id>/report', methods=['POST'])
@jwt_required
def create_report(id):
    report_reason = request.json['reason']
    new_report = Report(report_reason, id)

    db.session.add(new_report)
    db.session.commit()


@app.route('/api/mod/reports', methods=['GET'])
@jwt_required
@require_permissions("mod")
def get_reports():
    all_reports = Report.query.all()
    result = reports_schema.dump(all_reports)
    return jsonify(result)


@app.route('/api/mod/reports/<id>', methods=['POST'])
@jwt_required
@require_permissions("mod")
def review_report(id):
    is_ok = request.json["isOk"]
    ban_user = request.json["banUser"]
    report = Report.query.get(id)

    if ban_user:
        advertisement = get_advertisement(report.advertisement)
        user = advertisement.owner
        user.delete_date = datetime.datetime.now() + datetime.timedelta(days=7)

    if is_ok:
        db.session.delete(id)

    db.session.commit()


@app.route("/api/mod/ban/<id>", methods=['POST'])
@jwt_required
@require_permissions("mod")
def ban_user(id):
    user = User.query.get(id)
    user.delete_date = datetime.datetime.now() + datetime.timedelta(days=7)

    db.session.commit()


@app.route('/api/categories', methods=['GET'])
@jwt_required
def get_categories():
    all_categories = Category.query.all()
    result = categories_schema.dump(all_categories)
    return jsonify(result)


@app.route('/api/chat', methods=["POST"])
@jwt_required
def create_conversation():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    person_b = request.json["id"]
    conversation = Conversation(user.id, person_b)

    db.session.add(conversation)
    db.session.commit()

    return conversation_schema.jsonify(conversation)


@app.route("/api/chat", methods=["GET"])
@jwt_required
def get_conversations():
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    conversations = Conversation.query.filter((Conversation.person_a == user.id) | (Conversation.person_b == user.id))

    return conversations_schema.jsonify(conversations)


@app.route("/api/chat/<id>", methods=["GET"])
@jwt_required
def get_conversation(id):
    messages = ChatMessage.query.filter_by(conversation=id)

    return messages_schema.jsonify(messages)


@app.route("/api/chat/<id>", methods=["POST"])
@jwt_required
def create_message(id):
    current = get_jwt_identity()
    try:
        user = User.find_by_email(current)
    except FileNotFoundError:
        return {'message': 'No such user'}
    conversation = Conversation.query.get(id)
    message_text = request.json["message"]
    direction = True

    if user.id is conversation.person_b:
        direction = False

    message = ChatMessage(message_text, direction, id)

    db.session.add(message)
    db.session.commit()

    messages = ChatMessage.query.filter_by(conversation=id)

    return messages_schema.jsonify(messages)


@app.route("/api/admin/price", methods=["POST"])
@jwt_required
def set_price():
    new_price = request.json["newPrice"]
    price = AppSettings.query.filter_by(key="price").first()

    if price is None:
        price = AppSettings("price", new_price)
        db.session.add(price)
    else:
        price.value = new_price

    db.session.commit()


@app.route('/api/admin/users', methods=['GET'])
@jwt_required
@require_permissions("admin")
def get_users():
    all_users = User.query.all()
    result = users_details_schema.dump(all_users)
    return jsonify(result)


@app.route('/api/admin/users/<id>', methods=['PUT'])
@jwt_required
@require_permissions("admin")
def change_moderator_status(id):
    user = User.query.get(id)
    is_moderator = request.json["isModerator"]
    user.is_moderator = is_moderator

    db.session.commit()

    return user_details_schema.jsonify(user)


@app.route('/api/admin/categories', methods=['POST'])
@jwt_required
@require_permissions("admin")
def create_category():
    name = request.json['category_name']
    new_category = Category(name)

    db.session.add(new_category)
    db.session.commit()

    return category_schema.jsonify(new_category)


@app.route('/api/admin/categories/<id>', methods=['DELETE'])
@jwt_required
@require_permissions("admin")
def delete_category(id):
    category = Category.query.get(id)
    db.session.delete(category)
    db.session.commit()
    return category_schema.jsonify(category)


def send_email(email, access_token):
    msg = Message(subject='Activation', body='localhost:8000/api/activate/{}/{}'.format(access_token,email),
                  sender='ogloszenioofka@nuke.africa', recipients=[email])
    mail.send(msg)
    return 'Email sent!'


if __name__ == '__main__':
    db.create_all()
    app.run(port=8000, debug=True, host='0.0.0.0')
