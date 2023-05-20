from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)
    favorite_people = db.relationship('FavoritePeople', backref = 'user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.name

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name
            # do not serialize the password, its a security breach
        }
class People(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    height = db.Column(db.Float, unique=False, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)
    mass = db.Column(db.String(80), unique=False, nullable=False)
    hair_color = db.Column(db.String(80), unique=False, nullable=False)
    favorite_people = db.relationship('FavoritePeople', backref= 'people', lazy=True)
    
    def serialize(self):
        return {
            "id": self.id,        
            "name": self.name,
            "height": self.height,
            "mass": self.mass,
            "hair_color":self.hair_color
            # do not serialize the password, its a security breach
        }
    
class FavoritePeople (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    people_id = db.Column(db.Integer, db.ForeignKey('people.id'), nullable=False)

    def serialize(self):
        return {
            "id": self.id,
            "people_id": self.people_id,
            "user_id": self.user_id,
            "people_name": People.query.get(self.people_id).serialize()["name"],
            "user_name": User.query.get(self.user_id).serialize()["name"],
            "user":User.query.get(self.user_id).serialize(),
            "people":People.query.get(self.people_id).serialize()
        }

class TokenBlockedList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=False)
    created_at = db.Column(db.DateTime, nullable=False)

    def serialize(self):
        return {
            "id":self.id,
            "token":self.token,
            "email":self.email,
            "created":self.created_at
        }