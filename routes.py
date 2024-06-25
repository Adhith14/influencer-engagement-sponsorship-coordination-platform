from flask import flash, redirect, render_template, request, url_for, session
from app import app
from models import db,User,Sponsor, Influencer
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps

#decorator for auth_required for session check

def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return wrapper

#-------------------------------------------index

@app.route('/')

def index():
    # return render_template('index.html')
    user_id = session.get('user_id')
    user = None
    user2 = None
    if user_id:
        user = User.query.get(user_id)
    return render_template('index.html', user=user, user2=user2)

#-------------------------------------------login

@app.route('/login')
def login():
    return render_template('login.html')


# -------------------------------------------login post
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.passhash, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login'))
    
    session['user_id'] = user.user_id
    flash('Login successful')
    return redirect(url_for('profile'))

# -------------------------------------------sponsor registration

@app.route('/sponsor-register')
def register():
    return render_template('sponsor-register.html')

# -------------------------------------------influencer registration

@app.route('/influencer-register')
def register2():
    return render_template('influencer-register.html')

# -------------------------------------------sponsor registration post
@app.route('/sponsor-register', methods=['POST'])
def register_sponsor():
    username=request.form.get('username')
    password=request.form.get('password')
    company=request.form.get('company')
    industry=request.form.get('industry')
    budget=request.form.get('budget')

    if not username or not password or not company or not industry or not budget:
        flash('Please enter all the fields', 'error')
        return redirect(url_for('register_sponsor'))
    
    user=User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists', 'error')
        return redirect(url_for('register_sponsor'))


    password_hash = generate_password_hash(password)
    
    new_user = User(username=username, passhash=password_hash, role='sponsor')
    db.session.add(new_user)
    db.session.commit()

    new_sponsor= Sponsor(sponsor_id=new_user.user_id,company_name=company, industry=industry, budget=budget)
    db.session.add(new_sponsor)
    db.session.commit()

    return redirect(url_for('login'))

#-------------------------------------------influencer registration post
@app.route('/influencer-register', methods=['POST'])
def register_influencer():
    username=request.form.get('username')
    password=request.form.get('password')
    name=request.form.get('name')
    category=request.form.get('category')
    niche=request.form.get('niche')
    reach=request.form.get('reach')

    if not username or not password or not name or not category or not niche or not reach:
        flash('Please enter all the fields', 'error')
        return redirect(url_for('register_influencer'))
    
    user=User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists', 'error')
        return redirect(url_for('register_influencer'))
    
    password_hash = generate_password_hash(password)

    new_user = User(username=username, passhash=password_hash, role='influencer')
    db.session.add(new_user)
    db.session.commit()

    new_influencer = Influencer(influencer_id=new_user.user_id, name=name, category=category, niche=niche, reach=reach)
    db.session.add(new_influencer)
    db.session.commit()

    return redirect(url_for('login'))

#-------------------------------------------profile

@app.route('/profile')
@auth_required
def profile():
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user.role == 'admin':
        return render_template('adminProfile.html', user=user)
    elif user.role == 'sponsor':
        sponsor=Sponsor.query.get(user_id)
        return render_template('sponsorProfile.html', user=user, user2=sponsor)
    else:
        influencer=Influencer.query.get(user_id)
        return render_template('influProfile.html', user=user, user2=influencer)
    
#-------------------------------------------edit profile
@app.route('/profile' , methods=['POST'])
@auth_required

def profile_post():
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        return adminProfile_post()
    elif user.role == 'sponsor':
        return sponsorProfile_post()
    else:
        return influencerProfile_post()


def adminProfile_post():
    username=request.form.get('username')
    curr_password=request.form.get('curr_password')
    new_password=request.form.get('new_password')

    if not username or not curr_password or not new_password:
        flash('Please enter all the fields', 'error')
        return redirect(url_for('profile'))
    user=User.query.get(session['user_id'])
    if not check_password_hash(user.passhash, curr_password):
        flash('Please enter correct current password', 'error')
        return redirect(url_for('profile'))
    if username!=user.username:
        new_username=User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists', 'error')
            return redirect(url_for('profile'))
    
    new_password_hash = generate_password_hash(new_password)
    user.username=username
    user.passhash=new_password_hash
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))

def sponsorProfile_post():
    username=request.form.get('username')
    curr_password=request.form.get('curr_password')
    new_password=request.form.get('new_password')
    company=request.form.get('company')
    industry=request.form.get('industry')
    budget=request.form.get('budget')
    if not username or not curr_password or not new_password or not company or not industry or not budget:
        flash('Please enter all the fields', 'error')
        return redirect(url_for('profile'))
    user=User.query.get(session['user_id'])
    sponsor=Sponsor.query.get(session['user_id'])
    if not check_password_hash(user.passhash, curr_password):
        flash('Please enter correct current password', 'error')
        return redirect(url_for('profile'))
    if username!=user.username:
        new_username=User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists', 'error')
            return redirect(url_for('profile'))
    new_password_hash = generate_password_hash(new_password)
    user.username=username
    user.passhash=new_password_hash
    sponsor.company_name=company
    sponsor.industry=industry
    sponsor.budget=budget
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))


def influencerProfile_post():
    username=request.form.get('username')
    curr_password=request.form.get('curr_password')
    new_password=request.form.get('new_password')
    name=request.form.get('name')
    category=request.form.get('category')
    niche=request.form.get('niche')
    reach=request.form.get('reach')
    if not username or not curr_password or not new_password or not name or not category or not niche or not reach:
        flash('Please enter all the fields', 'error')
        return redirect(url_for('profile'))
    user=User.query.get(session['user_id'])
    influencer=Influencer.query.get(session['user_id'])
    if not check_password_hash(user.passhash, curr_password):
        flash('Please enter correct current password', 'error')
        return redirect(url_for('profile'))
    if username!=user.username:
        new_username=User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists', 'error')
            return redirect(url_for('profile'))
    new_password_hash = generate_password_hash(new_password)
    user.username=username
    user.passhash=new_password_hash
    influencer.name=name
    influencer.category=category
    influencer.niche=niche
    influencer.reach=reach
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))

#-------------------------------------------logout
@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    flash('You have been logged out')
    return redirect(url_for('login'))