"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, send_from_directory
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from api.utils import APIException, generate_sitemap
from api.models import db
from api.routes import api
from api.admin import setup_admin
from api.models import db, User, People, FavoritePeople, TokenBlockedList
from api.commands import setup_commands
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
#from models import Person
from datetime import date, time, datetime, timezone, timedelta

from flask_bcrypt import Bcrypt

ENV = os.getenv("FLASK_ENV")
static_file_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../public/')
app = Flask(__name__)
app.url_map.strict_slashes = False

app.config["JWT_SECRET_KEY"] = os.getenv("FLASK_APP_KEY")  # Change this!
jwt = JWTManager(app)
bcrypt = Bcrypt(app)


# database condiguration
db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MIGRATE = Migrate(app, db, compare_type = True)
db.init_app(app)

# Allow CORS requests to this API
CORS(app)

# add the admin
setup_admin(app)

# add the admin
setup_commands(app)

# Add all endpoints form the API with a "api" prefix
app.register_blueprint(api, url_prefix='/api')

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)


def verificacionToken(jti):
    jti#Identificador del JWT (es más corto)
    print("jit", jti)
    token = TokenBlockedList.query.filter_by(token=jti).first()

    if token is None:
        return False
    
    return True

# any other endpoint will try to serve it like a static file
@app.route('/user', methods=['GET'])
def handle_hello():
    users = User.query.all()  #<User Antonio>
    users = list(map(lambda item: item.serialize(), users))
    print(users)
  
    return jsonify(users), 200

@app.route('/login', methods=['POST'])
def login():
    email=request.get_json()["email"]
    password = request.get_json()["password"]

    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"message":"No existe el usuario"}), 401

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message":"Contraseña erronea"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({"token":access_token}), 200

@app.route('/register', methods=['POST'])
def register_user():
   
    body = request.get_json() 
    email = body["email"]
    name = body["name"]
    password = body["password"]
    is_active = body["is_active"]

    if body is None:
        raise APIException("You need to specify the request body as json object", status_code=400)
    if "email" not in body:
        raise APIException("You need to specify the email", status_code=400)

    password_encrypted = bcrypt.generate_password_hash(password,10).decode("utf-8")

    new_user = User(email=email, name=name, password=password_encrypted, is_active=is_active)

    db.session.add(new_user) 
    db.session.commit()

    return jsonify({"mensaje":"Usuario creado correctamente"}), 201 
@app.route('/get-user/<int:id>', methods=['GET'])
def get_specific_user(id):
    user = User.query.get(id)    
  
    return jsonify(user.serialize()), 200

@app.route('/get-user', methods=['POST'])
def get_specific_user2():
    body = request.get_json()   
    id = body["id"]

    user = User.query.get(id)   
  
    return jsonify(user.serialize()), 200

@app.route('/get-user', methods=['DELETE'])
def delete_specific_user():
    body = request.get_json()   
    id = body["id"]

    user = User.query.get(id) 

    db.session.delete(user)
    db.session.commit()  
  
    return jsonify("Usuario borrado"), 200

@app.route('/get-user', methods=['PUT'])
def edit_user():
    body = request.get_json()   
    id = body["id"]
    name = body["name"]

    user = User.query.get(id)   
    user.name = name 
    db.session.commit()
  
    return jsonify(user.serialize()), 200

@app.route('/add-favorite/people', methods=['POST'])
def add_favorite_people():
    body = request.get_json()
    user_id = body["user_id"]
    people_id = body["people_id"]

    character = People.query.get(people_id)
    if not character:
        raise APIException('personaje no encontrado', status_code=404)
    
    user = User.query.get(user_id)
    if not user:
        raise APIException('usuario no encontrado', status_code=404)

    fav_exist = FavoritePeople.query.filter_by(user_id = user.id, people_id = character.id).first() is not None
    
    if fav_exist:
        raise APIException('el usuario ya lo tiene agregado a favoritos', status_code=404)

    favorite_people = FavoritePeople(user_id=user.id, people_id=character.id)
    db.session.add(favorite_people)
    db.session.commit()

    return jsonify(favorite_people.serialize()), 201


@app.route('/favorites', methods=['POST'])
def list_favorites():
    body = request.get_json()
    user_id = body["user_id"]
    if not user_id:
        raise APIException('faltan datos', status_code=404)
    
    user = User.query.get(user_id)
    if not user:
        raise APIException('usuario no encontrado', status_code=404)

    user_favorites = FavoritePeople.query.filter_by(user_id=user.id).all()    
    user_favorites_final = list(map(lambda item: item.serialize(), user_favorites))

    return jsonify(user_favorites_final), 200


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    token = verificacionToken(get_jwt()["jti"])
    print(token)
    if token:
       raise APIException('Token está en lista negra', status_code=404)

    print("EL usuario es: ", user.name)
    return jsonify({"message":"Estás en una ruta protegida", "name": user.name}), 200

@app.route("/logout", methods=["GET"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"] 
    now = datetime.now(timezone.utc) 

    
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    tokenBlocked = TokenBlockedList(token=jti , created_at=now, email=user.email)
    db.session.add(tokenBlocked)
    db.session.commit()

    return jsonify({"message":"logout successfully"})


if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3001))
    app.run(host='0.0.0.0', port=PORT, debug=True)