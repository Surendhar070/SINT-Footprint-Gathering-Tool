"""
Firebase configuration for OSINT Footprint Gathering Tool
Firebase JS SDK v7.20.0+ compatible (measurementId optional)
"""

# Firebase project config - used for Auth REST API
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyAblxd8QSYf5yc3cNIjm9P89_wRIkhM09c",
    "authDomain": "osint-footprint-gathering.firebaseapp.com",
    "databaseURL": "https://osint-footprint-gathering-default-rtdb.firebaseio.com",
    "projectId": "osint-footprint-gathering",
    "storageBucket": "osint-footprint-gathering.firebasestorage.app",
    "messagingSenderId": "467051692641",
    "appId": "1:467051692641:web:b404d948261e8762f4a020",
    "measurementId": "G-1W35NHTGNT",
}

# Firebase Auth REST API base URLs
FIREBASE_AUTH_SIGNUP_URL = (
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
)
FIREBASE_AUTH_SIGNIN_URL = (
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
)
