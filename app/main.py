from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Wale wiadro'

if __name__ == '__main__':
    app.run(port=8000,debug=True, host='0.0.0.0')