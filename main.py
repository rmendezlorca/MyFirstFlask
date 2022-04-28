from flask import Flask, request, jsonify, make_response
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
import logging
from flask_swagger_ui import get_swaggerui_blueprint

logger = logging.getLogger(__name__)
SWAGGER_URL = '/api/docs'
API_URL ='https://myfirstflask.ricardomendez8.repl.co/v2/swagger.json'

#app = Flask(__name__)
app = Flask('app')
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite://///home/runner/MyFirstFlask/library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
db.create_all()
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        logger.info(args)
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
            #app.logger.info("entro aqui"+str(data))
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
            print("current_user es "+str(current_user.username))
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator
@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'registered successfully'})
@app.route('/login', methods=['GET', 'POST'])  
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    user = Users.query.filter_by(name=auth.username).first()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token})
    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})
@app.route('/users', methods=['GET'],endpoint='my-resource')
@token_required
def get_all_users(current_user):
    users = Users.query.all()
    result = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        result.append(user_data)
    return jsonify({'users': result})
@app.route('/')
def hello_world():
  return 'Hello, World!'
@app.route('/hellowworldspanish/', methods=['GET'])
def hellow_world_spanish():
  return "Hola Mundo"
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Test application"
    },
    # oauth_config={  # OAuth config. See https://github.com/swagger-api/swagger-ui#oauth2-configuration .
    #    'clientId': "your-client-id",
    #    'clientSecret': "your-client-secret-if-required",
    #    'realm': "your-realms",
    #    'appName': "your-app-name",
    #    'scopeSeparator': " ",
    #    'additionalQueryStringParams': {'test': "hello"}
    # }
)
app.register_blueprint(swaggerui_blueprint)

app.run(host='0.0.0.0', port=8080)
