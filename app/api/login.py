from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)
from app.models.breaches import get_passwords_from_breaches

@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    # Login
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != password:
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    # Register
    elif (request.forms.get("register")):
        breached_passwords = get_passwords_from_breaches(db, username)
        if password in breached_passwords:
            response.status = 401
            error = "Breached password for {}. Try a different password.".format(username)
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")
