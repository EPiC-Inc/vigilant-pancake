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


###ANCHOR: Classes
class User:
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
    if old_token and get_session(old_token):
        del sessions[old_token]
    new_token = str(uuid.uuid4()).encode('ascii')
    sessions[new_token] = Session()
    return new_token


###ANCHOR: Handlers
class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        session_token = self.get_secure_cookie("session")
        return get_session(session_token)

class EchoWebSocket(BaseHandler):
    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        self.write_message(u"You said: " + message)

    def on_close(self):
        print("WebSocket closed")



class LoginHandler(BaseHandler):
    def get(self):
        session_token = self.get_secure_cookie("session")
        if not session_token:
            self.set_secure_cookie("session", set_session())
            self.write("Your cookie was not set yet!")

        elif not get_session(session_token):
            self.set_secure_cookie("session", set_session())
            self.write("You have no valid session!")

        else:
            self.write("You're in a valid session!")
    
    def post(self):
        # Check credentials
        if valid_creds: # type: ignore
            session_token = self.get_secure_cookie("session")
            set_session(session_token)
        else:
            pass

class CommsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.write('comms go here')
        pass

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")
        return
        session_token = self.get_secure_cookie("session")
        if not session_token:
            session_token = str(uuid.uuid4()).encode('ascii')
            self.set_secure_cookie("session", str(uuid.uuid4()))
            self.write("Your cookie was not set yet!")
            sessions[session_token] = Session()

        elif not get_session(session_token):
            session_token = str(uuid.uuid4()).encode('ascii')
            self.set_secure_cookie("session", session_token)
            self.write("You have no valid session!")
            sessions[session_token] = Session()

        else:
            self.write("You're in a valid session!")




### Routing
def make_app():
    return tornado.web.Application([
        ('/', MainHandler),
        ('/login', LoginHandler),
        ('/comms*', CommsHandler),
    ],
    ### Options
    cookie_secret = "da6f7af0-8f13-489e-9573-4708037b97e5",
    login_url = "/login",
    template_path = "templates",
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