from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    category_name = db.Column(db.String(80), unique = True, nullable = False)

    def __repr__(self):
        return self.category_name


@app.route('/')
def index():
    return 'Wale wiadro'

if __name__ == '__main__':
    app.run(port=8000,debug=True, host='0.0.0.0')