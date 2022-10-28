# imports
import asyncio
import datetime as dt
#import json
import os
import pickle
import random
import uuid
from dataclasses import dataclass
from html import escape

import bcrypt
import cryptography
import requests
import tornado.auth
import tornado.escape
import tornado.locks
import tornado.web
import tornado.websocket
from dotenv import load_dotenv

load_dotenv()

###ANCHOR: Global variables
SESSIONS = {}
ROOMS = {}
#TODO: migrate to a proper database
USERS_FILE = "users"
OAUTH_FILE = "oauth_bindings"
USERS = {}
OAUTHS = {}
try:
    with open(USERS_FILE, 'rb') as json_file:
        USERS = pickle.load(json_file)
except FileNotFoundError:
    pass

try:
    with open(OAUTH_FILE, 'rb') as json_file:
        OAUTHS = pickle.load(json_file)
except FileNotFoundError:
    pass

urandom = random.SystemRandom()



###ANCHOR: Classes
@dataclass
class User:
    '''User class for the program'''
    id: str
    display_name: str | None = None
    password: bytes | None = None
    oauth: dict = {}
    pfp: str | None = None
    global_role: int = 0

    def verify(self) -> bool:
        '''Checks if the user is a valid user and has login capability'''
        can_login = bool(self.password) or bool(self.oauth)
        return can_login

    def create(self, password: str) -> tuple[bool, str]:
        success, message = self.set_password(password)
        if not success:
            return (success, message)
        if not self.display_name:
            self.display_name = self.id
        self.save()
        return (True, "User created and saved")

    def create_oauth(self, oauth_method: str, oauth_id: str) -> tuple[bool, str]:
        match oauth_method:
            case 'twitter' | 'fuck you this is a placeholder so i remember what i\'m doing here':
                if not self.oauth[oauth_method]:
                    self.oauth[oauth_method] = oauth_id
                else:
                    return (False, "Error: oauth.already_set_for_user")
            case _:
                return (False, "Error: oauth.provider_unknown")
        self.save()
        return (True, f"User created with oauth provider {oauth_method}\
             and saved")

    def set_password(self, new_password) -> tuple[bool, str]:
        '''Sets the users password to the new_password'''
        # Verify whether new password is valid / strong enough
        if len(new_password) > 4:
            self.password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            return (True, "Password changed successfully")
        return (False, "Password is not strong enough")

    def save(self) -> None:
        ''' this is terrible and should be replaced with a database asap '''
        USERS[self.id] = self.__dict__
        with open(USERS_FILE, 'wb') as outfile:
            pickle.dump(USERS, outfile, protocol=pickle.HIGHEST_PROTOCOL)
        if not (self.oauth == {}):
            with open(OAUTH_FILE, 'wb') as outfile:
                pickle.dump(OAUTHS, outfile, protocol=pickle.HIGHEST_PROTOCOL)

"""     def __init__(self, id):
        if id:
            self.properties = SimpleNamespace(**USERS.get(id))  # type: ignore

        user = {
            "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None,
            # Oauth is stored in the form {'site': user_id,}
            "oauth": oauth,
            "display_name": display_name if display_name else id,
            "pfp_link": None,
            "global_role": global_role,
        } """

class Session:
    def __init__(self, user=None):
        self.valid_until = dt.datetime.now()
        self.valid_until += dt.timedelta(hours=20)
        self.user = user
        self.key = None
        self.prime = None

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

def login(username, password, oauth=None):
    username = username.lower()
    match oauth:
        case None:
            user = USERS.get(username, None)
            if not user:
                return (False, "User not found")
            if not user.get('password'):
                return (False, "User has logged in with OAuth but has not set up a password yet.<br>Either that, or something is terribly wrong lol")
            if bcrypt.checkpw(password.encode(), user.get('password')):
                return (True, "Login successful")
            return (False, "Password incorrect")
        case "twitter":
            return (False, "not implemented yet lmao")
    return (False, "This shouldn't happen - please contact Labs or submit a ticket with error code \'auth.missing_case\'")

def save_user(oauth=False):
    ''' this is terrible and should be replaced with a database asap '''
    with open(USERS_FILE, 'wb') as outfile:
        pickle.dump(USERS, outfile, protocol=pickle.HIGHEST_PROTOCOL)
    if oauth:
        with open(OAUTH_FILE, 'wb') as outfile:
            pickle.dump(OAUTHS, outfile, protocol=pickle.HIGHEST_PROTOCOL)

def create_user(id, password, confirm_password, oauth=False, display_name=None, pfp_link=None, global_role=0):
    id = id.lower()
    if not password and not oauth:
        return (False, "No password provided")
    if id in USERS:
        return (False, "User ID already in use")
    if password != confirm_password:
        return (False, "Passwords do not match")
    user = {
        "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None,
        # Oauth is stored in the form {'site': user_id,}
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

class DiffieHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print('key channel open')
        session_token = self.get_secure_cookie("session")
        self.session = get_session(session_token)
        # Send "common paint"
        sharedBase = 12#urandom.randint(100000, 999999)      # g
        sharedPrime = 17#urandom.randint(100000, 999999)    # p
        self.prime = sharedPrime
        key = urandom.randint(100000, 999999)

        # Alice Sends Bob A = g^a mod p
        A = (sharedBase**key) % sharedPrime
        self.write_message({'base':sharedBase, 'prime':sharedPrime})
        self.session.key = key # type: ignore
        self.mix = A

    def on_message(self, message):
        print( "\n  Alice Sends Over Public Chanel: " , self.mix)
        self.write_message({'mix':self.mix, 'prime':self.prime})
        print( "   Bob Sends Over Public Chanel: ", message )
        key = int(message) ** self.session.key # type: ignore
        key = key % self.prime # type: ignore
        self.session.key = key # type: ignore
        print( "    Alice Shared Secret: ", self.session.key) # type: ignore
        self.close()

    def on_close(self):
        print("key channel closed")

class ChatHandler(tornado.websocket.WebSocketHandler):
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
        if signup == "signup-twitter":
            print(self.get_current_user().oauth_id) # type: ignore
            self.render("__oauth_new_account.html")
            return
        elif signup == "login-twitter":
            print(self.get_current_user().oauth_id) # type: ignore
            self.render("__oauth_link_account.html")
            return
        elif signup:
            self.render("signup.html", message='')
        else:
            self.render("login.html", message='')

    def post(self, signup=False):
        username = self.get_argument('username').lower()
        password = self.get_argument('password', None)
        if signup:
            page_to_go = signup if not "-" in str(signup) else "__oauth_new_account"
            success, message = create_user(username, password, self.get_argument('password-repeat', None), self.get_current_user().oauth_id is not None if self.get_current_user() else False)
            if not success:
                self.render(f"{page_to_go}.html", message=message)
                return
            if signup == "login-twitter" and self.get_current_user().oauth_id: # type: ignore
                print("2222idididid")
            old_token = self.get_secure_cookie("session")
            self.set_secure_cookie("session", set_session(username, old_token))
            self.redirect(self.get_argument('next', '/'))
            return
        #TODO: do actual credential checking
        # Check credentials
        success, message = login(username, password)
        if success:
            if signup == "login-twitter" and self.get_current_user().oauth_id: # type: ignore
                print("IDDIDIDIID")
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



### OAUTH handlers
class TwitterLoginHandler(BaseHandler,
                          tornado.auth.TwitterMixin):
    async def get(self):
        if self.get_argument("oauth_token", None) and self.get_argument("oauth_verifier", None):
            # getting the info the hard way i guess lmao
            user = requests.post('https://api.twitter.com/oauth/access_token', data={
                "oauth_consumer_key": os.environ['twitter_consumer_key'],
                "oauth_token": self.get_argument("oauth_token"),
                "oauth_verifier": self.get_argument("oauth_verifier"),
            })
            user = str(user.content).split("&")
            user_id=user[2][8:]

            old_token = self.get_secure_cookie("session")
            new_token = set_session(None,old_token)
            self.set_secure_cookie("session", new_token)
            if OAUTHS['twitter'].get(user_id):
                # Try to login the user
                success, message = login(OAUTHS['twitter'].get(user_id), None, 'twitter')
                if success:
                    get_session(new_token).user = User(user_id) # type: ignore
                    pass #TODO: finish authentication
                else:
                    self.render("login.html", message="This should not be happening. Please contact Labs or submit a ticket with the error code \'oauth.out_of_sync\'")
            else:
                get_session(new_token).oauth_id = user_id # type: ignore
                self.redirect('/signup-twitter')
            #print(user)
            a = self.get_current_user()
            print(a)
            # Save the user using e.g. set_secure_cookie()
        else:
            await self.authorize_redirect()



### Routing
def make_app():
    return tornado.web.Application([
        # these are all regex. makes sense? eh kinda
        ('/', MainHandler),
        ('/home', MainHandler),
        ('/(.*-policy)', MainHandler),
        ('/(favicon.png)', tornado.web.StaticFileHandler, {'path':'static'}),
        #style.css
        #style-dark.css
        #style-light.css
        ('/(style.*\\.css)', tornado.web.StaticFileHandler, {'path':'static'}),
        ('/js/(.*\\.js)', tornado.web.StaticFileHandler, {'path':'static\\js'}),
        ('/(announcements)', MainHandler),
        ('/login', LoginHandler),
        ('/(signup)', LoginHandler),
        ('/(signup-twitter)', LoginHandler),
        ('/comms', CommsHandler),
        ('/comms/(.*)', CommsHandler),
        ('/settings', SettingsHandler),
        ('/echo/(.*)', ChatHandler),
        ('/echo', ChatHandler),
        ('/gen_key', DiffieHandler),

        ('/login/twitter', TwitterLoginHandler),
    ],
    ### Options
    cookie_secret = os.environ['cookie_secret'],
    login_url = "/login",
    template_path = "templates",
    #default_handler_class = ErrorHandler,
    #default_handler_args = {'status_code': 404},
    compiled_template_cache = False, #TEMP
    twitter_consumer_key=os.environ['twitter_consumer_key'],
    twitter_consumer_secret=os.environ['twitter_consumer_secret'],
    )



### Start server
async def main():
    app = make_app()
    app.listen(int(os.environ['PORT']) if os.environ.get('PORT') else 80)
    await asyncio.Event().wait()

if __name__ == "__main__":
    print("[i] Starting server...")
    asyncio.run(main())
