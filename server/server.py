from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return {"message": "Hello, World!"}

@app.route('/message')
def message():
    return {"message": "Hello, World!"}


if __name__ == '__main__':
    app.run(debug=True, port=5001) 