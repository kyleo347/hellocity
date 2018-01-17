import os
import re
import webapp2
import jinja2
import hmac,hashlib
import time, logging
from google.appengine.ext import db
from google.appengine.api import memcache
import random, string, json


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)
SECRET = '#%$ERe45r7urfe8ioj*()IYUH4y5egH^&UTER#645hrf675'
logging.getLogger().setLevel(logging.DEBUG)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def test_hash(s, s_hash):
    return s_hash==hmac.new(SECRET, s).hexdigest()
	
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
	
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)
	
def valid_password(password,verify):
    if password == verify:
        match=re.match("^.{3,20}$", password)
        if match:
           return match.string

def valid_username(username):
        match=re.match("^[a-zA-Z0-9_-]{3,20}$",username)
        if match:
            return match.string

def valid_email(email):
		match = re.match("^[\S]+@[\S]+\.[\S]+$", email)
		if match:
		    return match.string

def top_posts(update = False):
        key, time_key = 'mainpage', 'mainpagetime'
        Posts = memcache.get(key)
        qtime = memcache.get(time_key)
        if Posts is None or qtime is None or update:
                Posts = db.GqlQuery("SELECT * "
                                        "FROM Post "
                                        "ORDER BY created DESC "
                                        "LIMIT 10")
                Posts = list(Posts)
                qtime = time.time()
                memcache.set(time_key, qtime)
                memcache.set(key, Posts)
        return Posts, qtime
	
class User(db.Model):
    username = db.StringProperty(required = True)
    passhash = db.StringProperty(required = True)
    email = db.StringProperty()

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))		

class MainPage(Handler):
    def render_front(self, posts, last_load, subject="", content="", error=""):
        self.render("front.html", posts = posts, last_load = last_load)
    def get(self, jsonFlag):
        posts, qtime = top_posts()
        last_load = time.time()-qtime
        if jsonFlag:
            response = []
            for post in posts:
                response.append({'content': post.content, 'created':str(post.created), 'subject': post.subject})
            self.response.content_type = 'application/json'
            self.response.write(json.dumps(response))
        else:
            self.render_front(posts, last_load)
			
class NewBlogPage(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error = error)
    def get(self):
        self.render_front()
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            a = Post(subject = subject, content = content)
            a.put()
            top_posts(True)
            self.redirect('/%s' % str(a.key().id()))
        else:
            error = "we need both subject and content!"
            self.render_front(subject, content, error)
			
class SinglePost(Handler):
    def get(self, post_id, jsonFlag):
        post = memcache.get(post_id)
        if post is None:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            memcache.set(post_id, post)
            memcache.set(post_id + 'time', time.time())
        if jsonFlag:
            response = json.loads('{"content": "%s", "created": "%s", "subject": "%s"}' % (post.content, post.created, post.subject))
            self.response.content_type = 'application/json'
            self.response.write(json.dumps(response))
        else:
            last_load = time.time() - memcache.get(post_id + 'time')
            self.render("SinglePost.html", post = post, last_load = last_load)
		
class Delete(Handler):
    def get(self):
        db.delete(Post.all())
        self.response.write('Success!')
		
class Flush(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')

class SignupPage(Handler):
    
    def get(self):
        self.render("signup.html", error='', username='', password='', verify='', email='')
        #self.write_form()

    def post(self):
	
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        error=''

        username = str(valid_username(user_username))
        password = str(valid_password(user_password,user_verify))
        email = valid_email(user_email)
		
        if not username:
        	error+='<br> Invalid username.'
        if not password:
        	error+='<br> Invalid password or verification.'
        if not email and user_email != '':
        	error+='<br> Invalid email.'
        	
        if error:
        	self.render("signin.html", error=error, username=username, email=user_email)
        else:
            a = User(username=username, key_name=username, passhash=make_pw_hash(username, password), email=user_email)
            a.put()
            user_id = str(a.key().id())
            self.redirect("/success")
            self.response.headers.add_header('Set-Cookie', 'name=%s|%s|%s; Path=/;' % (username, user_id, str(hash_str(username + user_id))))

class LoginPage(Handler):
    
    def get(self):
        self.render("login.html", error='', username='', password='', verify='', email='')
        #self.write_form()

    def post(self):
	
        username = str(self.request.get('username'))
        password = str(self.request.get('password'))
        error=''

        key = db.Key.from_path('User', username)
        user = db.get(key)
        if user:
            pass_salt = user.passhash
            salt = pass_salt.split(',')[1]
        	
            if pass_salt == make_pw_hash(username,password,salt):
                self.redirect("/success")
                user_id = str(user.key().id())
                self.response.headers.add_header('Set-Cookie', 'name=%s|%s|%s; Path=/;' % (username, user_id, str(hash_str(username + user_id))))

        else:
        	self.render("login.html", error='Invalid username/password.', username=username)

class SuccessPage(Handler):
    def get(self):
        userhash = self.request.cookies.get('name')
        userhash = userhash.split('|')
        if test_hash(userhash[0] + userhash[1], userhash[2]):
            self.response.out.write("Welcome, %s!" % userhash[0])
        else:
            self.redirect('/signup')
			
class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'name=; Path=/')
        self.redirect('/signup')

app = webapp2.WSGIApplication([('/signup', SignupPage),
                              ('/success', SuccessPage),
							  ('/login', LoginPage),
							  ('/logout', LogoutPage),
							  ('/?(.json)?', MainPage),
							  ('/newpost', NewBlogPage),
							  ('/delete', Delete),
							  ('/([0-9]+)(.json)?', SinglePost),
							  ('/flush',Flush)],
                             debug=True)