from models import Base, User, OAuthMembership, Request,Proposal,MealDate
from flask import Flask, jsonify, request, url_for, abort, g, redirect,render_template,flash,make_response
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, or_, and_

from oauth import OAuthSignIn
from flask import session as login_session

from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

import random,string

engine = create_engine('sqlite:///meatneat.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
          'id': '470154729788964',
          'secret': '010cc08bd4f51e34f3f3e684fbdea8a7'
      },
      'google': {
          'id': '763910754530-rqig5i0qt95f2832bdkg15m49580rhtl.apps.googleusercontent.com',
          'secret': 'KA5kZILEXedg8SuQsied7MfW'
      },
      'twitter': {
          'id': '3RzWQclolxWZIMq5LJqzRZPTl',
          'secret': 'm9TEd58DSEtRrZHpz2EjrV9AhsBRxKMo8m3kuIZj3zLwzwIimt'
      },
}


@auth.verify_password
def verify_password(username_or_token, password):
    #Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True



@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

@auth.error_handler
def unauthorized():
    return make_response(jsonify( { 'error': 'Unauthorized access' } ), 403)
    # return 403 instead of 401 to prevent browsers from displaying the default auth dialog

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify( { 'error': 'Bad request' } ), 400)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)



@app.route('/')
@app.route('/index')
def index():
    if not login_session.get('username') :
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/oauth/<provider>')
def oauth_authorize(provider):
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email, picture = oauth.callback()
    user = session.query(User).filter_by(email=email).first()
    if not user:
        user = User(username = username, picture = picture, email = email)
        session.add(user)
        membership = OAuthMembership(provider = provider, provider_userid = social_id, user = user)
        session.add(membership)
        session.commit()
    login_session['username'] = user.username
    token = user.generate_auth_token(1600)

    return redirect(url_for('index', token = token))


@app.route('/api/v1/logout', methods = ['GET'])
@auth.login_required
def logout():
    g.user = None
    return jsonify({"result": True})

@app.route('/api/v1/login', methods = ['POST'])
def api_login():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        print "missing arguments"
        abort(400)
    username = request.json.get('username')
    password = request.json.get('password')
    user = session.query(User).filter_by(username = username).first()
    if not user or not user.verify_password(password):
        return jsonify({"result": False})
    token = user.generate_auth_token(6000)
    return jsonify({'token': token.decode('ascii')})


@app.route('/api/v1/users', methods= ['GET'])
@auth.login_required
def get_users():
    users = session.query(User).all()
    return jsonify(users = [u.serialize for u in users])

@app.route('/api/v1/users', methods= ['POST'])
def new_user():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        print "missing arguments"
        abort(400)
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        abort(400)
    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 409#, {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    token = user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

@app.route('/api/v1/users', methods=['PUT'])
@auth.login_required
def update_user():
    pass


@app.route('/api/v1/users/<int:id>', methods=['GET'])
@auth.login_required
def get_user(id):
    user = session.query(User).filter_by(id = id).first()
    if user is None:
        abort(404)
    return jsonify(user.serialize)

@app.route('/api/v1/requests', methods=['GET'])
@auth.login_required
def get_requests():
    user = g.user
    requests = session.query(Request).filter_by(user.id != User.user_id).all()
    return jsonify(requests = [r.serialize for r in requests])

@app.route('/api/v1/requests', methods=['POST'])
@auth.login_required
def new_request():
    pass


@app.route('/api/v1/requests/<int:id>', methods=['GET'])
@auth.login_required
def get_request(id):
    r = session.query(Request).filter_by(id = id).first()
    if r is None:
        abort(404)
    return jsonify(r.serialize)


@app.route('/api/v1/requests/<int:id>', methods=['PUT'])
@auth.login_required
def update_request(id):
    pass

@app.route('/api/v1/requests/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_request(id):
    user = g.user
    r = session.query(Request).filter_by(id = id).first()
    if r is None:
        abort(404)
    if user.id != r.user_id:
        abort(403)
    session.delete(r)
    session.commit()
    return  jsonify( { 'result': True } )

@app.route('/api/v1/proposals', methods=['GET'])
@auth.login_required
def get_proposals():
    user = g.user
    proposals = session.query(Proposal).filter(or_(Proposal.user_proposed_to == user.id, Proposal.user_proposed_from == user.id)).all()
    return jsonify(requests = [proposal.serialize for proposal in proposals])

@app.route('/api/v1/proposals', methods=['POST'])
@auth.login_required
def new_proposal():
    pass

@app.route('/api/v1/proposals/<int:id>', methods=['GET'])
@auth.login_required
def get_proposal(id):
    user = g.user
    proposal = session.query(Proposal).filter_by(id = id).first()
    if proposal is None:
        abort(404)
    if proposal.user_proposed_to != user.id and proposal.user_proposed_from != user.id:
        abort(403)
    return jsonify(proposal.serialize)

@app.route('/api/v1/proposals/<int:id>', methods=['PUT'])
@auth.login_required
def update_proposal(id):
    pass

@app.route('/api/v1/proposals/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_proposal(id):
    proposal = session.query(Proposal).filter_by(id = id).first()
    if proposal is None:
        abort(404)
    if proposal.user_proposed_from != user.id:
        abort(403)
    session.delete(proposal)
    session.commit()
    return  jsonify( { 'result': True } )

@app.route('/api/v1/dates', methods=['GET'])
@auth.login_required
def get_dates():
    user = g.user
    dates = session.query(MealDate).filter(or_(MealDate.user_1 == user.id, MealDate.user_2 == user.id)).all()
    return jsonify(dates = [date.serialize for date in dates])


@app.route('/api/v1/dates', methods=['POST'])
@auth.login_required
def new_date():
    pass

@app.route('/api/v1/dates/<int:id>', methods=['GET'])
@auth.login_required
def get_date(id):
    user = g.user
    date = session.query(MealDate).filter_by(id = id).first()
    if date is None:
        abort(404)
    if date.user_1 != user.id and date.user_2 != user.id:
        abort(403)
    return jsonify(date.serialize)

@app.route('/api/v1/dates/<int:id>', methods=['PUT'])
@auth.login_required
def update_date():
    pass

@app.route('/api/v1/dates/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_date(id):
    date = session.query(MealDate).filter_by(id = id).first()
    if date is None:
        abort(404)
    if date.user_1 != user.id and date.user_2 != user.id:
        abort(403)
    session.delete(date)
    session.commit()
    return  jsonify( { 'result': True } )


if __name__ == '__main__':
    app.debug = True
    app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
