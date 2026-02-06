import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps

# Set to True to print API errors in the terminal (e.g. 401 = bad key, 429 = rate limit)
_DEBUG_API = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def _api_headers():
    """RapidAPI key: set RAPIDAPI_KEY in environment or .env (e.g. export RAPIDAPI_KEY=your_key)."""
    key = os.environ.get("RAPIDAPI_KEY", "")
    return {
        "X-RapidAPI-Key": key,
        "X-RapidAPI-Host": "online-movie-database.p.rapidapi.com",
    }


def lookup(title):
    url = "https://online-movie-database.p.rapidapi.com/title/v2/find"
    q = {"title": title, "titleType": "movie,tvSeries,tvMiniSeries", "limit": "25", "sortArg": "moviemeter,asc"}
    headers = _api_headers()

    if not headers.get("X-RapidAPI-Key"):
        if _DEBUG_API:
            print("[API] lookup: RAPIDAPI_KEY is not set. Add it to .env or export RAPIDAPI_KEY=your_key")
        return []

    try:
        response = requests.get(url, headers=headers, params=q, timeout=10)
        search = response.json()
        if response.status_code != 200:
            if _DEBUG_API:
                print("[API] lookup failed:", response.status_code, search)
            return []
        return search.get("results", [])
    except (requests.RequestException, KeyError, ValueError) as e:
        if _DEBUG_API:
            print("[API] lookup error:", e)
        return []


def look(title):
    url = "https://online-movie-database.p.rapidapi.com/title/find"
    q = {"q": title}
    headers = _api_headers()

    if not headers.get("X-RapidAPI-Key"):
        return []

    try:
        response = requests.get(url, headers=headers, params=q, timeout=10)
        search = response.json()
        if response.status_code != 200:
            if _DEBUG_API:
                print("[API] look failed:", response.status_code, search)
            return []
        return search.get("results", [])
    except (requests.RequestException, KeyError, ValueError) as e:
        if _DEBUG_API:
            print("[API] look error:", e)
        return []

def rating(title):
    url = "https://online-movie-database.p.rapidapi.com/title/get-ratings"
    q = {"tconst": title}
    headers = _api_headers()

    if not headers.get("X-RapidAPI-Key"):
        return "N/A"

    try:
        response = requests.get(url, headers=headers, params=q, timeout=10)
        if response.status_code != 200:
            return "N/A"
        raw = response.json()
        return raw.get("rating", "N/A")
    except (requests.RequestException, KeyError, ValueError):
        return "N/A"
