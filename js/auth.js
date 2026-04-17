/**
 * Firebase Auth for website: login, register, 1‑minute sign‑in prompt
 */
(function () {
  'use strict';

  if (typeof firebase === 'undefined') return;

  if (!firebase.apps.length) {
    firebase.initializeApp(typeof firebaseConfig !== 'undefined' ? firebaseConfig : {});
  }
  var auth = firebase.auth();

  function getAuthBannerEl() {
    return document.getElementById('auth-prompt-banner');
  }

  function showAuthBanner() {
    if (sessionStorage.getItem('auth-banner-dismissed')) return;
    var el = getAuthBannerEl();
    if (!el) return;
    el.classList.add('auth-banner-visible');
  }

  function hideAuthBanner() {
    var el = getAuthBannerEl();
    if (el) el.classList.remove('auth-banner-visible');
    sessionStorage.setItem('auth-banner-dismissed', '1');
  }

  function updateNavForUser(user) {
    var loginLi = document.getElementById('nav-login');
    var registerLi = document.getElementById('nav-register');
    var logoutLi = document.getElementById('nav-logout-wrap');
    if (!loginLi && !logoutLi) return;
    if (user) {
      if (loginLi) loginLi.style.display = 'none';
      if (registerLi) registerLi.style.display = 'none';
      if (logoutLi) {
        logoutLi.style.display = 'list-item';
        var emailEl = document.getElementById('nav-user-email');
        if (emailEl) emailEl.textContent = user.email || 'Signed in';
      }
      hideAuthBanner();
    } else {
      if (loginLi) loginLi.style.display = 'list-item';
      if (registerLi) registerLi.style.display = 'list-item';
      if (logoutLi) logoutLi.style.display = 'none';
    }
  }

  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'nav-logout') {
      e.preventDefault();
      if (window.AuthHelper) window.AuthHelper.signOut();
    }
    if (e.target && e.target.classList && e.target.classList.contains('banner-dismiss')) {
      e.preventDefault();
      hideAuthBanner();
    }
  });

  auth.onAuthStateChanged(function (user) {
    updateNavForUser(user);
  });

  window.AuthHelper = {
    auth: auth,
    showBanner: showAuthBanner,
    hideBanner: hideAuthBanner,
    signOut: function () {
      auth.signOut();
      sessionStorage.removeItem('auth-banner-dismissed');
      window.location.href = 'index.html';
    }
  };

  /** Start 1‑minute timer: show Firebase sign‑in prompt if not logged in */
  function startOneMinuteTimer() {
    if (document.getElementById('auth-prompt-banner') && !sessionStorage.getItem('auth-banner-dismissed')) {
      setTimeout(function () {
        auth.onAuthStateChanged(function (user) {
          if (!user) showAuthBanner();
        });
      }, 60 * 1000);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startOneMinuteTimer);
  } else {
    startOneMinuteTimer();
  }
})();
