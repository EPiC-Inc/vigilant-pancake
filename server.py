# imports
import asyncio
import datetime as dt
import os
import uuid
from requests import session

import tornado.escape
import tornado.locks
import tornado.web
import tornado.websocket

###ANCHOR: Global variables
sessions = {}
rooms = {}
#TODO: load users

###ANCHOR: Classes
class User:
    def __init__(self, id):
        pass

class Session:
    def __init__(self, user=None):
        self.valid_until = dt.datetime.now()
        self.valid_until += dt.timedelta(hours=20)
        self.user = user

    def validate(self):
        return self.valid_until > dt.datetime.now()


###ANCHOR: Functions
def get_session(token):
    session = sessions.get(token)
    if not session:
        return None
    if session.validate():
        return session
    else:
        del sessions[token]
        return None

def set_session(old_token=None):
    # Kill old session if needed
    if old_token and get_session(old_token):
        del sessions[old_token]
    new_token = str(uuid.uuid4()).encode('ascii')
    sessions[new_token] = Session()
    return new_token

def login(username, password):
    if username=="test" and password=="test":
        return True
    return False

#def create_user(id, password, display_name=None, pfp_link=None, global_role=0)


###ANCHOR: Handlers
class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        session_token = self.get_secure_cookie("session")
        return get_session(session_token)

class SocketHandler(tornado.websocket.WebSocketHandler):
    def get_current_user(self):
        session_token = self.get_secure_cookie("session")
        return get_session(session_token)

    def open(self, command=None):
        if not self.get_current_user():
            self.close()
            return
        print("WebSocket opened with command", command)

    def on_message(self, message):
        self.write_message(u"You said: " + message)

    def on_close(self):
        print("WebSocket closed")



class LoginHandler(BaseHandler):
    def get(self, signup=False):
        if signup:
            self.render("signup.html", message='')
        else:
            self.render("login.html", message='')

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        #TODO: do actual credential checking
        # Check credentials
        if login(username, password):
            session_token = self.get_secure_cookie("session")
            self.set_secure_cookie("session", set_session())
            set_session(session_token)
            if self.get_argument('next', None):
                self.redirect(self.get_argument('next'))
            else:
                self.redirect('/')
            #TODO: redirect user
        else:
            self.render("login.html", message='Wrong username or password')

class CommsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, room=None):
        self.write('comms go here')
        pass

class SettingsHandler(BaseHandler):
    #@tornado.web.authenticated
    def get(self):
        self.render("settings.html")

class ErrorHandler(BaseHandler):
    def prepare(self):
        self.set_status(404)

    def write_error(self, status_code=404, exc_info=None):
        status_code = self.get_status()
        self.render("404.html", error_info=status_code)

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")



### Routing
def make_app():
    return tornado.web.Application([
        # these are all regex. makes sense? eh kinda
        ('/', MainHandler),
        ('/(favicon.png)', tornado.web.StaticFileHandler, {'path':'static'}),
        #style.css
        #style-dark.css
        #style-light.css
        ('/(style.*\.css)', tornado.web.StaticFileHandler, {'path':'static'}),
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
    app.listen(8080)
    await asyncio.Event().wait()

if __name__ == "__main__":
    print("[i] Starting server...")
    asyncio.run(main())
