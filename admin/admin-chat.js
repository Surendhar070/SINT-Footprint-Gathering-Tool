/**
 * Admin: fetch and display all live chat messages from Firebase Realtime Database.
 * Shows sender name, email, and message. Live updates via .on('value').
 */
(function () {
  'use strict';

  if (typeof firebase === 'undefined') {
    document.getElementById('admin-messages').innerHTML = '<tr><td colspan="4">Firebase not loaded.</td></tr>';
    return;
  }

  if (!firebase.apps.length) {
    firebase.initializeApp(typeof firebaseConfig !== 'undefined' ? firebaseConfig : {});
  }
  var db = firebase.database();
  var CHAT_REF = 'support_chat/messages';

  var tbody = document.getElementById('admin-messages');
  var countEl = document.getElementById('admin-count');
  var refreshBtn = document.getElementById('admin-refresh');

  function escapeHtml(s) {
    if (s == null || s === undefined) return '';
    var div = document.createElement('div');
    div.textContent = String(s);
    return div.innerHTML;
  }

  function formatDateTime(ts) {
    if (ts == null) return '—';
    var d = new Date(typeof ts === 'number' ? ts : ts);
    return d.toLocaleString(undefined, {
      dateStyle: 'short',
      timeStyle: 'short'
    });
  }

  function renderAll(snap) {
    var rows = [];
    snap.forEach(function (child) {
      var d = child.val();
      if (!d) return;
      var ts = formatDateTime(d.timestamp);
      var name = escapeHtml(d.name || '—');
      var email = escapeHtml(d.email || '—');
      var msg = escapeHtml(d.message || '—');
      rows.push(
        '<tr><td class="col-ts">' + ts + '</td><td>' + name + '</td><td class="col-email" title="' + email + '">' + email + '</td><td class="col-msg">' + msg + '</td></tr>'
      );
    });

    tbody.innerHTML = rows.length
      ? rows.join('')
      : '<tr><td colspan="4" class="admin-empty">No messages yet.</td></tr>';
    if (countEl) countEl.textContent = rows.length + ' message(s)';
  }

  var q = db.ref(CHAT_REF).orderByChild('timestamp');
  q.on('value', renderAll);

  if (refreshBtn) {
    refreshBtn.addEventListener('click', function () {
      refreshBtn.disabled = true;
      refreshBtn.textContent = 'Refreshing…';
      q.once('value').then(function (snap) {
        renderAll(snap);
        refreshBtn.disabled = false;
        refreshBtn.textContent = 'Refresh';
      }).catch(function () {
        refreshBtn.disabled = false;
        refreshBtn.textContent = 'Refresh';
      });
    });
  }
})();
