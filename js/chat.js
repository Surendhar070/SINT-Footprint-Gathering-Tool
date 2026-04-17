/**
 * Support chat using Firebase Realtime Database
 * Requires Firebase SDK loaded and firebase-config.js
 */
(function () {
  'use strict';

  if (typeof firebase === 'undefined') {
    console.warn('Firebase SDK not loaded. Chat disabled.');
    return;
  }

  if (!firebase.apps.length) firebase.initializeApp(typeof firebaseConfig !== 'undefined' ? firebaseConfig : {});
  const db = firebase.database();
  const CHAT_REF = 'support_chat/messages';

  const messagesEl = document.getElementById('chat-messages');
  const formEl = document.getElementById('chat-form');
  const inputEl = document.getElementById('chat-input');
  const nameEl = document.getElementById('chat-name');
  const emailEl = document.getElementById('chat-email');

  if (!messagesEl || !formEl || !inputEl) return;

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(typeof ts === 'number' ? ts : ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function renderMessage(data, isOwn) {
    const div = document.createElement('div');
    div.className = 'chat-msg ' + (isOwn ? 'own' : 'guest');
    const name = escapeHtml(data.name || 'Guest');
    const msg = escapeHtml(data.message || '');
    const time = formatTime(data.timestamp);
    const email = data.email ? ' &middot; ' + escapeHtml(data.email) : '';
    div.innerHTML = '<div class="meta">' + name + email + ' &middot; ' + time + '</div>' + msg;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  const ownIds = new Set();

  const q = db.ref(CHAT_REF).orderByChild('timestamp').limitToLast(80);
  q.on('child_added', function (snap) {
    const d = snap.val();
    if (!d) return;
    const isOwn = ownIds.has(snap.key);
    renderMessage(d, isOwn);
  });

  formEl.addEventListener('submit', function (e) {
    e.preventDefault();
    const name = (nameEl && nameEl.value.trim()) || 'Guest';
    const email = (emailEl && emailEl.value.trim()) || '';
    const message = inputEl.value.trim();
    if (!message) return;

    const payload = {
      name: name.slice(0, 80),
      email: email.slice(0, 120),
      message: message.slice(0, 2000),
      timestamp: Date.now()
    };

    const ref = db.ref(CHAT_REF).push();
    ownIds.add(ref.key);
    ref.set(payload).then(function () {
      inputEl.value = '';
    }).catch(function (err) {
      console.error('Chat send error:', err);
      alert('Could not send message. Check console and Firebase Realtime Database rules.');
    });
  });
})();
