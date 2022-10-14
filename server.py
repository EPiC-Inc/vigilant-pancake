# imports
import asyncio
import datetime as dt
import json
import os
import pickle
import uuid
from types import SimpleNamespace
from html import escape

import bcrypt
import tornado.escape
import tornado.locks
import tornado.web
import tornado.websocket

###ANCHOR: Global variables
SESSIONS = {}
ROOMS = {}
USERS_FILE = "users"
USERS = {}
try:
    with open(USERS_FILE, 'rb') as json_file:
        USERS = pickle.load(json_file)
except:
    pass
#TODO: load users



###ANCHOR: Classes
class User:
    def __init__(self, id):
        self.properties = SimpleNamespace(**USERS.get(id))  # type: ignore

class Session:
    def __init__(self, user=None):
        self.valid_until = dt.datetime.now()
        self.valid_until += dt.timedelta(hours=20)
        self.user = user

    def validate(self):
        return self.valid_until > dt.datetime.now()



###ANCHOR: Functions
def get_session(token):
    #print("Checking session")
    session = SESSIONS.get(token)
    if not session:
        return None
    if session.validate():
        return session
    else:
        del SESSIONS[token]
        return None

def set_session(username, old_token=None):
    # Kill old session if needed
    if old_token and get_session(old_token):
        del SESSIONS[old_token]
    new_token = str(uuid.uuid4()).encode('ascii')
    SESSIONS[new_token] = Session(user=User(username))
    return new_token

def login(username, password):
    username = username.lower()
    user = USERS.get(username, None)
    if not user:
        return (False, "User not found")
    if bcrypt.checkpw(password.encode(), user.get('password')):
        return (True, "Login successful")
    return (False, "Password incorrect")

def save_user(user=None):
    ''' this is terrible and should be replaced with a database asap '''
    with open(USERS_FILE, 'wb') as outfile:
        pickle.dump(USERS, outfile, protocol=pickle.HIGHEST_PROTOCOL)

def create_user(id, password, confirm_password, oauth=False, display_name=None, pfp_link=None, global_role=0):
    id = id.lower()
    if id in USERS:
        return (False, "User ID already in use")
    if password != confirm_password:
        return (False, "Passwords do not match")
    user = {
        "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
        "oauth": oauth,
        "display_name": display_name if display_name else id,
        "pfp_link": None,
        "global_role": global_role,
    }
    USERS[id] = user
    save_user()
    return (True, "User created")



###ANCHOR: Handlers
class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        session_token = self.get_secure_cookie("session")
        return get_session(session_token)

class SocketHandler(tornado.websocket.WebSocketHandler):
    def get_current_user(self):
        session_token = self.get_secure_cookie("session")
        return get_session(session_token)

    def open(self, room="lobby"):
        if not ROOMS.get(room):
            ROOMS[room] = set()
        ROOMS[room].add(self)
        self.room = room
        #print(ROOMS)#TEMP
        if not self.get_current_user():
            self.close()
            return
        self.user = self.get_current_user().user.properties #type: ignore
        #print(self.user)#TEMP
        print("WebSocket opened with command", room)#TEMP

    def on_message(self, message):
        message = message.strip()[:1500]
        message = escape(str(message))
        if not message:
            return
        #TODO: Construct message
        message = f"[{self.user.display_name}] {message}"
        for user in ROOMS[self.room]:
            user.write_message(message)

    def on_close(self):
        ROOMS[self.room].remove(self)
        print("WebSocket closed")#TEMP

class LoginHandler(BaseHandler):
    def get(self, signup=False):
        if signup:
            self.render("signup.html", message='')
        else:
            self.render("login.html", message='')

    def post(self, signup=False):
        username = self.get_argument('username')
        password = self.get_argument('password')
        if signup:
            success, message = create_user(username, password, self.get_argument('password-repeat', None))
            if not success:
                self.render("signup.html", message=message)
                return
            old_token = self.get_secure_cookie("session")
            self.set_secure_cookie("session", set_session(username, old_token))
            self.redirect('/comms')
            return
        #TODO: do actual credential checking
        # Check credentials
        success, message = login(username, password)
        if success:
            old_token = self.get_secure_cookie("session")
            self.set_secure_cookie("session", set_session(username, old_token))
            self.redirect(self.get_argument('next', '/'))
        else:
            self.render("login.html", message=message)

    def put(self):
        self.write('success')

class CommsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, room=None):
        self.render('comms.html', room=room)

class SettingsHandler(BaseHandler):
    #@tornado.web.authenticated
    def get(self):
        self.render("settings.html")

    def post(self):
        self.render("settings.html")

class ErrorHandler(BaseHandler):
    def prepare(self):
        self.set_status(404)

    def write_error(self, status_code=404, exc_info=None):
        status_code = self.get_status()
        self.render("404.html", error_info=status_code)

class MainHandler(BaseHandler):
    def get(self, page=None):
        #print(self.get_current_user())
        if page:
            self.render(str(page)+".html")
        else:
            if self.get_current_user():
                self.render('index_logged_in.html')
                return
            self.render("index.html")



### Routing
def make_app():
    return tornado.web.Application([
        # these are all regex. makes sense? eh kinda
        ('/', MainHandler),
        ('/home', MainHandler),
        ('/(favicon.png)', tornado.web.StaticFileHandler, {'path':'static'}),
        #style.css
        #style-dark.css
        #style-light.css
        ('/(style.*\\.css)', tornado.web.StaticFileHandler, {'path':'static'}),
        ('/(announcements)', MainHandler),
        ('/login', LoginHandler),
        ('/(signup)', LoginHandler),
        ('/comms', CommsHandler),
        ('/comms/(.*)', CommsHandler),
        ('/settings', SettingsHandler),
        ('/echo/(.*)', SocketHandler),
        ('/echo', SocketHandler),
    ],
    ### Options
    cookie_secret = "da6f7af0-8f13-489e-9573-4708037b97e5",
    login_url = "/login",
    template_path = "templates",
    default_handler_class = ErrorHandler,
    #default_handler_args = {'status_code': 404},
    compiled_template_cache = False, #TEMP
    )



### Start server
async def main():
    app = make_app()
    app.listen(int(os.environ['PORT']) if os.environ.get('PORT') else 8080)
    await asyncio.Event().wait()

if __name__ == "__main__":
    print("[i] Starting server...")
    asyncio.run(main())
