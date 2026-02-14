(function() {
  const PLUGIN_ID = 'ai-summary';

  function waitForNoteva(callback) {
    if (typeof Noteva !== 'undefined') callback();
    else setTimeout(function() { waitForNoteva(callback); }, 100);
  }

  waitForNoteva(function() {
    var settings = Noteva.plugins.getSettings(PLUGIN_ID);
    // Default is true — only skip if explicitly set to false
    if (settings.show_summary === false) return;

    var label = settings.summary_label || 'AI 摘要';
    // Cache: slug -> article id (from article_view hook)
    var _currentArticleId = null;

    function createSummaryBox(summary, articleId) {
      var box = document.createElement('div');
      box.className = 'ai-summary-box not-prose';
      var headerHtml =
        '<div class="ai-summary-header">' +
          '<span class="ai-summary-icon">✨</span>' +
          '<span class="ai-summary-label">' + label + '</span>' +
        '</div>';
      box.innerHTML = headerHtml +
        '<div class="ai-summary-content">' + summary + '</div>';

      // Only show regenerate button for admin users
      var currentUser = Noteva.user.getCurrent();
      if (currentUser && currentUser.role === 'admin') {
        var btn = document.createElement('button');
        btn.className = 'ai-summary-regenerate';
        btn.title = '重新生成';
        btn.textContent = '🔄';
        btn.addEventListener('click', function() {
          regenerateSummary(articleId, box);
        });
        box.querySelector('.ai-summary-header').appendChild(btn);
      }
      return box;
    }

    function regenerateSummary(articleId, box) {
      var btn = box.querySelector('.ai-summary-regenerate');
      var contentEl = box.querySelector('.ai-summary-content');
      if (btn) { btn.disabled = true; btn.textContent = '⏳'; }
      if (contentEl) contentEl.textContent = '正在重新生成...';

      fetch('/api/v1/admin/plugins/' + PLUGIN_ID + '/action/regenerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ article_id: articleId })
      })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
          if (data && data.success && data.data && data.data.summary) {
            contentEl.textContent = data.data.summary;
          } else {
            // Refetch from storage (hook may have stored it)
            return fetch('/api/v1/plugins/' + PLUGIN_ID + '/data/summary:' + articleId)
              .then(function(r) { return r.ok ? r.json() : null; })
              .then(function(d) {
                if (d && d.value) contentEl.textContent = d.value;
                else contentEl.textContent = '重新生成失败，请稍后重试';
              });
          }
        })
        .catch(function() {
          if (contentEl) contentEl.textContent = '重新生成失败，请稍后重试';
        })
        .finally(function() {
          if (btn) { btn.disabled = false; btn.textContent = '🔄'; }
        });
    }

    function insertSummary(summary, articleId) {
      if (document.querySelector('.ai-summary-box')) return;
      // Prefer the PluginSlot for article_content_top
      var slot = document.querySelector('[data-noteva-slot="article_content_top"]');
      if (slot) {
        slot.appendChild(createSummaryBox(summary, articleId));
        return;
      }
      // Fallback: insert before article content
      var prose = document.querySelector('.prose');
      if (prose) {
        prose.insertBefore(createSummaryBox(summary, articleId), prose.firstChild);
        return;
      }
      // Last resort
      var article = document.querySelector('article');
      if (article) {
        var header = article.querySelector('header');
        if (header && header.nextElementSibling) {
          article.insertBefore(createSummaryBox(summary, articleId), header.nextElementSibling);
        }
      }
    }

    function fetchSummary(articleId) {
      if (!articleId) return;
      if (document.querySelector('.ai-summary-box')) return;

      fetch('/api/v1/plugins/' + PLUGIN_ID + '/data/summary:' + articleId)
        .then(function(resp) {
          if (!resp.ok) return null;
          var ct = resp.headers.get('content-type') || '';
          if (ct.indexOf('application/json') === -1) return null;
          return resp.json();
        })
        .then(function(data) {
          if (data && data.value) insertSummary(data.value, articleId);
        })
        .catch(function() {});
    }

    function waitForSlotAndFetch(articleId, retries) {
      if (retries <= 0) return;
      if (document.querySelector('.ai-summary-box')) return;
      var slot = document.querySelector('[data-noteva-slot="article_content_top"]');
      if (slot || document.querySelector('.prose') || document.querySelector('article')) {
        fetchSummary(articleId);
      } else {
        setTimeout(function() { waitForSlotAndFetch(articleId, retries - 1); }, 200);
      }
    }

    // Primary: article_view hook — triggered by theme when loading article
    Noteva.hooks.on('article_view', function(article) {
      if (article && article.id) {
        _currentArticleId = article.id;
        // Remove old summary box on navigation
        var old = document.querySelector('.ai-summary-box');
        if (old) old.remove();
        // Wait for DOM to be ready, then fetch
        waitForSlotAndFetch(article.id, 15);
      }
    });

    // Fallback: content_render for SPA navigation
    Noteva.hooks.on('content_render', function() {
      // Only act on article pages
      var match = Noteva.router.match('/posts/:slug');
      if (!match || !match.matched) {
        // Not an article page — clean up any stale summary
        var old = document.querySelector('.ai-summary-box');
        if (old) old.remove();
        _currentArticleId = null;
        return;
      }
      // If article_view already provided the ID, use it
      if (_currentArticleId) {
        waitForSlotAndFetch(_currentArticleId, 15);
      }
      // Otherwise, article_view will fire soon from the theme
    });

    console.log('[Plugin] ai-summary loaded');
  });
})();
