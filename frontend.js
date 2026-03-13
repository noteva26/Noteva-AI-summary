(function () {
  const PLUGIN_ID = 'ai-summary';

  const I18N = {
    'zh-CN': { label: 'AI 摘要', regenerate: '重新生成', regenerating: '正在重新生成…', failed: '重新生成失败，请稍后重试' },
    'zh-TW': { label: 'AI 摘要', regenerate: '重新產生', regenerating: '正在重新產生…', failed: '重新產生失敗，請稍後重試' },
    'en': { label: 'AI Summary', regenerate: 'Regenerate', regenerating: 'Regenerating…', failed: 'Failed to regenerate. Please try again later.' },
  };

  function getLocale() {
    try {
      const stored = JSON.parse(localStorage.getItem('noteva-locale') || '{}');
      if (stored.state?.locale) return stored.state.locale;
    } catch (e) { }
    if (typeof Noteva !== 'undefined' && Noteva.i18n) return Noteva.i18n.getLocale();
    return 'zh-CN';
  }

  function t(key) {
    const locale = getLocale();
    const lang = locale.split('-')[0];
    const msgs = I18N[locale] || I18N[lang] || I18N['zh-CN'];
    return msgs[key] || key;
  }

  const ICON_SPARKLE = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1l2.09 6.26L20.18 9l-6.09 1.74L12 17l-2.09-6.26L3.82 9l6.09-1.74z"/><path d="M19 13l1.04 3.13L23.18 17l-3.14.87L19 21l-1.04-3.13L14.82 17l3.14-.87z" opacity=".6"/></svg>';
  const ICON_REFRESH = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>';
  const ICON_LOADING = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>';

  // Lightweight inline markdown: **bold**, *italic*, `code`, [link](url)
  function renderMd(text) {
    return text
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')  // escape HTML
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`(.+?)`/g, '<code>$1</code>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
      .replace(/\n/g, '<br>');
  }

  function waitForNoteva(callback) {
    if (typeof Noteva !== 'undefined') callback();
    else setTimeout(() => waitForNoteva(callback), 100);
  }

  waitForNoteva(function () {
    const settings = Noteva.plugins.getSettings(PLUGIN_ID);
    if (settings.show_summary === false) return;

    const label = settings.summary_label || t('label');
    let _currentArticleId = null;

    function createSummaryBox(summary, articleId) {
      const box = document.createElement('div');
      box.className = 'ai-summary-box not-prose';
      box.innerHTML = `
        <div class="ai-summary-header">
          <span class="ai-summary-icon">${ICON_SPARKLE}</span>
          <span class="ai-summary-label">${label}</span>
        </div>
        <div class="ai-summary-content">${renderMd(summary)}</div>`;

      const currentUser = Noteva.user.getCurrent();
      if (currentUser && currentUser.role === 'admin') {
        const btn = document.createElement('button');
        btn.className = 'ai-summary-regenerate';
        btn.title = t('regenerate');
        btn.innerHTML = ICON_REFRESH;
        btn.addEventListener('click', () => regenerateSummary(articleId, box));
        box.querySelector('.ai-summary-header').appendChild(btn);
      }
      return box;
    }

    function regenerateSummary(articleId, box) {
      const btn = box.querySelector('.ai-summary-regenerate');
      const contentEl = box.querySelector('.ai-summary-content');
      if (btn) { btn.disabled = true; btn.innerHTML = ICON_LOADING; btn.classList.add('spinning'); }
      if (contentEl) contentEl.textContent = t('regenerating');

      fetch('/api/v1/admin/plugins/' + PLUGIN_ID + '/action/regenerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ article_id: articleId }),
      })
        .then(resp => resp.json())
        .then(data => {
          if (data && data.success && data.data && data.data.summary) {
            contentEl.innerHTML = renderMd(data.data.summary);
          } else {
            return fetch('/api/v1/plugins/' + PLUGIN_ID + '/data/summary:' + articleId)
              .then(r => r.ok ? r.json() : null)
              .then(d => {
                contentEl.innerHTML = (d && d.value) ? renderMd(d.value) : t('failed');
              });
          }
        })
        .catch(() => { if (contentEl) contentEl.textContent = t('failed'); })
        .finally(() => {
          if (btn) { btn.disabled = false; btn.innerHTML = ICON_REFRESH; btn.classList.remove('spinning'); }
        });
    }

    function insertSummary(summary, articleId) {
      if (document.querySelector('.ai-summary-box')) return;
      const slot = document.querySelector('[data-noteva-slot="article_content_top"]');
      if (slot) { slot.appendChild(createSummaryBox(summary, articleId)); return; }
      const prose = document.querySelector('.prose');
      if (prose) { prose.insertBefore(createSummaryBox(summary, articleId), prose.firstChild); return; }
      const article = document.querySelector('article');
      if (article) {
        const header = article.querySelector('header');
        if (header && header.nextElementSibling) {
          article.insertBefore(createSummaryBox(summary, articleId), header.nextElementSibling);
        }
      }
    }

    function fetchSummary(articleId) {
      if (!articleId || document.querySelector('.ai-summary-box')) return;
      fetch('/api/v1/plugins/' + PLUGIN_ID + '/data/summary:' + articleId)
        .then(resp => {
          if (!resp.ok) return null;
          const ct = resp.headers.get('content-type') || '';
          if (ct.indexOf('application/json') === -1) return null;
          return resp.json();
        })
        .then(data => { if (data && data.value) insertSummary(data.value, articleId); })
        .catch(() => { });
    }

    function waitForSlotAndFetch(articleId, retries) {
      if (retries <= 0 || document.querySelector('.ai-summary-box')) return;
      if (document.querySelector('[data-noteva-slot="article_content_top"]') || document.querySelector('.prose') || document.querySelector('article')) {
        fetchSummary(articleId);
      } else {
        setTimeout(() => waitForSlotAndFetch(articleId, retries - 1), 200);
      }
    }

    Noteva.hooks.on('article_view', article => {
      if (article && article.id) {
        _currentArticleId = article.id;
        const old = document.querySelector('.ai-summary-box');
        if (old) old.remove();
        waitForSlotAndFetch(article.id, 15);
      }
    });

    Noteva.hooks.on('content_render', () => {
      const match = Noteva.router.match('/posts/:slug');
      if (!match || !match.matched) {
        const old = document.querySelector('.ai-summary-box');
        if (old) old.remove();
        _currentArticleId = null;
        return;
      }
      if (_currentArticleId) waitForSlotAndFetch(_currentArticleId, 15);
    });
  });
})();
