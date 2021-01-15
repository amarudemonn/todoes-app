from datetime import datetime
from functools import wraps
from flask import session, redirect

def login_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
      if session.get("user_id") is None:
          return redirect("/login")
      return f(*args, **kwargs)
  return decorated_function

def starts_with_number(string):
  return string[0].isdigit()

def contains_numbers(string):
  return any(char.isdigit() for char in string)

def get_current_date():
  return str(datetime.now()).split(".")[0]

def doesnt_have_symbols(string):
  result = True
  for char in string:
    if (not char.isdigit()) and (not char.isalpha()):
      result = False
  return result
