from flask_migrate import Migrate
from app import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash


db = SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(80), nullable=False)

class Sponsor(db.Model):
    sponsor_id = db.Column(db.Integer,db.ForeignKey('user.user_id'), primary_key=True)
    company_name = db.Column(db.String(80), unique=True, nullable=False)
    industry = db.Column(db.String(80), nullable=False)
    budget = db.Column(db.Float, nullable=False)
    flag = db.Column(db.Boolean, nullable=False, default=False)

class Influencer(db.Model):
    influencer_id = db.Column(db.Integer,db.ForeignKey('user.user_id'), db.ForeignKey('user.user_id'), primary_key=True)
    name= db.Column(db.String(80), unique=True, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    niche = db.Column(db.String(80), nullable=False)
    reach = db.Column(db.Integer, nullable=False)
    flag = db.Column(db.Boolean, nullable=False, default=False)

class Campaign(db.Model):
    campaign_id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer,db.ForeignKey('sponsor.sponsor_id'), nullable=False)
    name= db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    visibility = db.Column(db.String(10), nullable=False)
    goals = db.Column(db.Text, nullable=False)
    flag=db.Column(db.Boolean, nullable=False, default=False)

    sponsor=db.relationship('Sponsor',backref='campaign', lazy=True)
    ad_requests = db.relationship('AdRequest', backref='campaign', lazy=True)



class AdRequest(db.Model):
    ad_request_id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer,db.ForeignKey('campaign.campaign_id'), nullable=False)
    influencer_id = db.Column(db.Integer,db.ForeignKey('influencer.influencer_id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10), nullable=False, default="pending")
    flag = db.Column(db.Boolean, nullable=False, default=False)

    influencer = db.relationship('Influencer', backref='ad_requests', lazy=True)
    

with app.app_context():
    db.create_all()

    admin=User.query.filter_by(role='admin').first()
    if not admin:
        password_hash = generate_password_hash('admin')
        new_user = User(username='admin', passhash=password_hash, role='admin')
        db.session.add(new_user)
        db.session.commit()