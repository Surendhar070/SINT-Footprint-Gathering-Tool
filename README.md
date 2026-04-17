# OSINT Footprint Gathering Tool – Website

Professional website with **Home**, **About**, **Downloads**, and **Support & Chat** pages.  
Support chat uses **Firebase Realtime Database** for real-time messaging.

## Structure

```
website/
  index.html       # Home
  about.html       # About / features
  downloads.html   # Tool downloads
  support.html     # Support info + live chat
  install.html     # Installation guide
  admin/
    index.html     # Admin – live chat messages (sender email, message)
    admin-chat.js  # Fetch & display all messages from Realtime DB
  css/
    style.css      # Shared styles
  js/
    firebase-config.js  # Firebase config (matches firebase_config.py)
    chat.js             # Chat logic (Realtime Database)
```

## Running Locally

From the project root:

```bash
# Python
python -m http.server 8080

# Or Node (npx)
npx serve -p 8080
```

Then open `http://localhost:8080/website/` (or `http://localhost:8080` if you `cd website` first).

## Firebase Setup

1. **Realtime Database**  
   - Firebase Console → **Build** → **Realtime Database** → **Create database**.  
   - Choose a location, then **Enable**.

2. **Rules**  
   Use rules that allow read/write for `support_chat` (adjust as needed for auth later).  
   Add an index on `timestamp` so chat ordering works.  
   **Rules file**: `database.rules.json` in the project root.

   In Firebase Console → **Realtime Database** → **Rules**, paste the contents of `database.rules.json` (or the same structure below), then **Publish**:

```json
{
  "rules": {
    "support_chat": {
      "messages": {
        ".indexOn": ["timestamp"],
        ".read": true,
        ".write": true
      }
    }
  }
}
```

3. **Config**  
   `js/firebase-config.js` uses the same project as `firebase_config.py`.  
   Ensure `databaseURL` matches your Realtime Database URL.

## Downloads Page

`downloads.html` links to `../full-version0.zip` by default. Update the link to your installer or build artifact (e.g. output of `build_installer.bat` or your release URL).

## Chat

- **Support** → **Support & Chat**: name (required), email (optional), message.  
- Messages are stored under `support_chat/messages` with `name`, `email`, `message`, `timestamp`.  
- Chat works in-browser; no backend besides Firebase.

## Admin – Live Chat

- **`/website/admin/`**: Admin view of all support chat messages.  
- Lists **Time**, **Name**, **Email**, **Message** in a table. Live updates via Firebase.  
- **Refresh** refetches the list. Uses the same Realtime Database (`support_chat/messages`).  
- Open `http://localhost:8080/website/admin/` when serving locally.  
- Restrict access in production (e.g. Firebase Auth, server-side check, or firewall).
