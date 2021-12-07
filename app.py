from flask import render_template, flash, redirect, request, url_for
from flask_login import current_user, login_user, login_required, logout_user
import json
from flask import Flask, request, jsonify
from flask_mongoengine import MongoEngine
from flask_migrate import Migrate
import bcrypt
from flask_login import LoginManager

app = Flask(__name__)
migrate = Migrate()
app.config["DEBUG"] = True

login = LoginManager(app)
login.login_view = 'login'

app.config['MONGODB_SETTINGS'] = {
    'db' : "flasktask",
    'host' : "localhost",
    'port' : 27017
}

db = MongoEngine()
db.init_app(app)
#records = db.AdminUser

class templatetable(db.Document):
    templateName = db.StringField()
    subject = db.StringField()
    body = db.StringField()

    def to_json(self):
        return {
            "templatename": self.templateName,
            "subject": self.subject,
            "body": self.body
        }

from datetime import datetime
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

@login.user_loader
def load_user(id):
    return User.objects.get(id=id)

class User(UserMixin, db.Document):
    username = db.StringField(default=True)
    email = db.EmailField(unique=True)
    password_hash = db.StringField(default=True)


    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return "alreay logged in"
    else:
        data = json.loads(request.data)
        print(data)
        user = User.objects(email=data['email']).first()
        usepas = user.check_password(data['password'])

        print(user)
        for i in user:
            print(i)
    return "successfully login"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return "already login exisited"
        print("hello")
    else:
        print("heloo")
        data = json.loads(request.data)
        print(data)
        user = User(username=data['first_name'], email=data['email'])
        user.set_password(data['password'])
        user.save()

        usetdat = User.objects.all()
        return jsonify(usetdat.to_json())

    return jsonify(userdata.to_json())



def migrateflask():
    app = Flask(__name__)
    db = MongoEngine()
    db.init_app(app)
    migrate.init_app(app, db)
    return app

@app.route("/template", methods=["PUT"])
def newTemplate():
    print("hello")
    record = json.loads(request.data)
    print(record['templatename'])

    user = templatetable(templateName=record['templatename'],
                subject=record['subject'],
                body=record['body'])
    user.save()
    data = templatetable.objects.all()
    for i in data:
        print(i)
    print("data",user.to_json(),data)

    return jsonify(user.to_json())

@app.route('/alltemplates')
def alltemplates():
    print("all records")
    user = templatetable.objects.all()
    print(user)
    if not user:
        return jsonify({'error': 'data not found'})
    else:
        return jsonify(user.to_json())

@app.route('/SingleTemplates/')
def SingleTemplates():
    templateid = request.args.get('templateid')
    print(templateid)
    print("single records")
    user = templatetable.objects(id=templateid).first()
    print(user)
    if not user:
        return jsonify({'error': 'data not found'})
    else:
        return jsonify(user.to_json())

@app.route("/UpdateTemplate", methods=['PUT'])
def UpdateSingleTemplate():
    templateid = request.args.get('templateid')
    print(templateid)
    record = json.loads(request.data)
    user = templatetable.objects(id=templateid).first()

    updateTemplate = user.update(body=record['body'])
    print(updateTemplate)
    updateTemplate1 = templatetable.objects(id=templateid).first()
    return jsonify(updateTemplate1.to_json())

@app.route("/deleteTemplate", methods=['DELETE'])
def DELETESingleTemplate():
    templateid = request.args.get('templateid')
    print(templateid)
    delTmplt = templatetable.objects(id=templateid).first()
    delTmplt.delete()
    deleteTemplate = "Sucessfully deleted"
    return jsonify(deleteTemplate)

if __name__ == "__main__":
    app.run(debug=True)



