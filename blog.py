#!/usr/bin/env python
# -*- coding: utf-8 -*-

import webapp2
import cgi
import string
import os
import jinja2
import re
import datetime
from google.appengine.ext import db
import blogcrypt
import json
from google.appengine.api import memcache
import logging
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape = True,
	loader = jinja2.FileSystemLoader(template_dir))

def rot13(text):
	out = ''
	offset = 13
	aval = ord('a')
	Aval = ord('A')
	alp_range = ord('z') - ord('a') + 1

	for char in text:
		char_num = ord(char)
		if (char_num >= ord('a')) and (char_num <= ord('z')):
			new_char = ((char_num - aval + offset) % alp_range) + aval
			new_char = chr(new_char)
			out += new_char
		elif (char_num >= ord('A')) and (char_num <= ord('Z')):
			new_char = ((char_num - Aval + offset) % alp_range) + Aval
			new_char = chr(new_char)
			out += new_char
		else:
			out += char
	return out


class BaseHandler(webapp2.RequestHandler):
	def render(self,template, **kw):
		self.response.out.write(render_str(template,**kw))
	def write(self,*a,**kw):
		self.response.out(*a,**kw)

class Rot13(BaseHandler):
	def get(self):
		self.render('rot13.html')
	def post(self):
		text = self.request.get('text')
		enc_text = rot13(text)
		self.render('rot13.html',text =enc_text)


# ############################################################################
# BLOG STUFF HERE ------------------------------------------------------------
# ############################################################################


def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def blog_key(name = 'default'):
	return db.Key.from_path('entries',name)

def users_key(group = 'default'):
	return  db.Key.from_path('users', group)

class BlogHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def render_json(self,data):
		json_txt = json.dumps(data)
		self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
		self.write(json_txt)

	def set_secure_cookie(self,name,val):
		secure_cookie = blogcrypt.make_cookie_hash(str(val))
		self.response.set_cookie(name, secure_cookie)

	def read_secure_cookie(self, name):
		cookie = self.request.cookies.get(name)
		if cookie:
			return blogcrypt.check_cookie_hash(cookie)

	def login(self,user):
		self.set_secure_cookie('user_id',str(user.key().id()))

	def logout(self):
		self.response.set_cookie('user_id','')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

		if self.request.url.endswith('.json'):
			self.format = 'json'
		else:
			self.format = 'html'

class Signup(BlogHandler):
	def get(self):
		self.render('signup.html')
	def post(self):

		# setup regex expressions
		username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		password_re = re.compile(r"^.{3,20}$")
		email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

		# pull data from form
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		has_error = False
		fields = {}
		fields['username'] = username
		fields['email']  = email

		# perform validation checks
		if username_re.search(username) is None:
			has_error = True
			fields['username_error'] = "That's not a valid username"
		if password_re.match(password) is None:
			has_error = True
			fields['password_error'] = "That wasn't a valid password"
		if password != verify:
			has_error = True
			fields['verify_error'] = "Your passwords do not match"
		if email and (email_re.match(email) is None):
			has_error = True
			fields['email_error'] = 'Bad e-mail entered'

		# check is username already exists
		query =  db.GqlQuery("SELECT * FROM User WHERE username=:1", username)
		existing_users = query.get()
		if existing_users:
			has_error = True
			fields['username_error'] = "That user is already registered"
		if has_error:
			self.render('signup.html', **fields)
		else:
			if email:
				user  = User(username = username, password_hash = blogcrypt.make_pw_hash(username,password), email = email)
			else:
				user  = User(username = username, password_hash = blogcrypt.make_pw_hash(username,password))
			user.put() #stores user
			self.login(user)
			self.redirect('/blog/welcome')

class Login(BlogHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		# pull data from form
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username,password)

		if u:
			self.login(u)
			self.redirect('/blog/welcome')
		else:
			self.render('login.html', login_error="Invalid login")

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/blog/signup')

class Welcome(BlogHandler):
	def get(self):
		# if self.user:
		# self.render('welcome.html', self.user.name)
		user_id = self.request.cookies.get('user_id')
		if user_id:
			user_id = blogcrypt.check_cookie_hash(user_id)
		if not user_id:
			self.redirect('/blog/signup')
		else:
			key = db.Key.from_path('User',int(user_id))
			user = db.get(key)
			self.render('welcome.html',username = user.username)

class Submit(BlogHandler):
	def get(self):
		self.render('submit.html')
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			blog_post = Entry(subject=subject, content=content)
			blog_post.put() #stores the blog post
			front_entries(True); #update the cache when we add a post
			blog_id = blog_post.key().id()
			self.redirect('/blog/%s' % blog_id)
		else:
			error = "You need both a subject and content to be filled out"
			self.render('submit.html',subject=subject,content=content, error= error)

def front_entries(update = False):
	key = "frontpage"
	front_hash = memcache.get(key)

	if front_hash is None or update:
		logging.info("DB QUERY for FrontPage")
		entries = db.GqlQuery("SELECT * FROM Entry ORDER BY date_created DESC LIMIT 10")
		front_hash = {}
		front_hash['entries'] = list(entries)
		front_hash['time'] = time.time()
		memcache.set(key,front_hash)
	else:
		query_time = front_hash.get("time")
		if query_time is None:
			front_hash['time'] = time.time()
			memcache.set(key,front_hash)
	return front_hash

class FrontPage(BlogHandler):
	def get(self):
		out = front_entries()
		entries = out['entries']
		query_time = out['time']
		time_elapsed = time.time() - query_time
		if self.format == 'html':
			self.render("frontpage.html",entries=entries,time_elapsed=time_elapsed)
		elif self.format == 'json':
			front_list = []
			for entry in entries:
				front_list.append(entry.as_dict())
			self.render_json(front_list)


def permalink_cache(blog_id,update = False):
	mem_key = "permalink#%s" %(blog_id)
	entry_hash = memcache.get(mem_key)
	if entry_hash is None or update:
		logging.info("DB QUERY for Permalink# 	%s" %(blog_id))
		key = db.Key.from_path('Entry',int(blog_id))
		entry = db.get(key)
		if entry is None:
			return None
		entry_hash = {}
		entry_hash['entry'] = entry
		entry_hash['time'] = time.time()
		memcache.set(mem_key,entry_hash)
	else:
		query_time = entry_hash.get("time")
		if query_time is None:
			entry_hash['time'] = time.time()
			memcache.set(mem_key,entry_hash)
	return entry_hash

class Permalink(BlogHandler):
	def get(self, blog_id):
		entry_hash = permalink_cache(int(blog_id))
		if entry_hash:
			entry = entry_hash['entry']
			time_elapsed = time.time() - entry_hash['time']
			if self.format == 'html':
				self.render("permalink.html",entry=entry,time_elapsed=time_elapsed)
			elif self.format == 'json':
				self.render_json(entry.as_dict())
		else:
			self.error(404)
			return

class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.EmailProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid)

	@classmethod
	def by_name(cls, username):
		user = cls.all().filter('username = ',username).get()
		return user

	@classmethod
	def register(cls,name,pw,email = None):
		pw_hash = blogcrypt.make_pw_hash(name,pw)
		return cls(name = name, pw_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		user = cls.by_name(name)
		if user and blogcrypt.check_pw_hash(name,pw, user.password_hash):
			return user

class Entry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		return render_str("entry.html", entry = self)

	def as_dict(self):
		d = {
		'subject': self.subject,
		'content': self.content,
		'created': self.date_created.strftime('%a %b %d %H:%M:%S %Y'),
		'last_modified': self.last_modified.strftime('%a %b %d %H:%M:%S %Y')
		}
		return d

app = webapp2.WSGIApplication([('/unit2/rot13/?',Rot13),
							   ('/blog/signup/?',Signup),
							   ('/blog/welcome/?',Welcome),
							   ('/blog/newpost/?',Submit),
							   ('/blog/([0-9]+)(?:\.json)?',Permalink),
							   ('/blog/login/?',Login),
							   ('/blog/logout/?',Logout),
							   ('/blog/?(?:\.json)?',FrontPage)],
							   debug=True)
