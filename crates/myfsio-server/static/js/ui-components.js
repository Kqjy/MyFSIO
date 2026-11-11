window.UI = (function() {
  'use strict';

  function resolve(target) {
    if (!target) return null;
    if (typeof target === 'string') return document.querySelector(target);
    return target;
  }

  function placeNear(floating, anchor, options) {
    var gap = (options && options.gap) || 6;
    var preferAbove = !!(options && options.above);
    var alignEnd = !!(options && options.alignEnd);
    var center = !!(options && options.center);
    var a = anchor.getBoundingClientRect();
    var f = floating.getBoundingClientRect();
    var vw = document.documentElement.clientWidth;
    var vh = document.documentElement.clientHeight;
    var left = center ? a.left + (a.width - f.width) / 2 : (alignEnd ? a.right - f.width : a.left);
    left = Math.max(8, Math.min(left, vw - f.width - 8));
    var below = a.bottom + gap;
    var above = a.top - f.height - gap;
    var top = preferAbove ? above : below;
    if (preferAbove && above < 8) top = below;
    if (!preferAbove && below + f.height > vh - 8 && above >= 8) top = above;
    floating.style.left = Math.round(left) + 'px';
    floating.style.top = Math.round(Math.max(8, top)) + 'px';
  }

  var dialog = {
    open: function(target, opener) {
      var el = resolve(target);
      if (!el || el.open) return el;
      el._uiOpener = opener || document.activeElement;
      el.showModal();
      el.dispatchEvent(new CustomEvent('ui:open'));
      return el;
    },
    close: function(target, returnValue) {
      var el = resolve(target);
      if (el && el.open) el.close(returnValue);
    }
  };

  document.addEventListener('click', function(event) {
    var opener = event.target.closest('[data-ui-open]');
    if (opener) {
      event.preventDefault();
      dialog.open(opener.getAttribute('data-ui-open'), opener);
      return;
    }
    var closer = event.target.closest('[data-ui-close]');
    if (closer) {
      var owner = closer.closest('dialog');
      if (owner) {
        event.preventDefault();
        dialog.close(owner, closer.getAttribute('data-ui-close') || '');
      }
      return;
    }
    if (event.target instanceof HTMLDialogElement && event.target.classList.contains('ui-dialog') && !event.target.hasAttribute('data-ui-static')) {
      var box = event.target.getBoundingClientRect();
      var inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top && event.clientY <= box.bottom;
      if (!inside) dialog.close(event.target);
    }
  });

  document.addEventListener('close', function(event) {
    var el = event.target;
    if (!(el instanceof HTMLDialogElement)) return;
    var opener = el._uiOpener;
    el._uiOpener = null;
    if (opener && document.contains(opener) && typeof opener.focus === 'function') opener.focus();
  }, true);

  function menuItems(menu) {
    return Array.prototype.filter.call(menu.querySelectorAll('.ui-menu-item'), function(item) {
      return !item.disabled && item.getAttribute('aria-disabled') !== 'true';
    });
  }

  function menuTrigger(menu) {
    return menu.id ? document.querySelector('[popovertarget="' + CSS.escape(menu.id) + '"]') : null;
  }

  var menu = {
    open: function(target, anchor) {
      var el = resolve(target);
      if (!el) return;
      el._uiAnchor = anchor || menuTrigger(el);
      el.showPopover();
    },
    openAt: function(target, x, y) {
      var el = resolve(target);
      if (!el) return;
      el._uiAnchor = null;
      el._uiPoint = { x: x, y: y };
      el.showPopover();
    },
    close: function(target) {
      var el = resolve(target);
      if (el && el.matches(':popover-open')) el.hidePopover();
    }
  };

  document.addEventListener('toggle', function(event) {
    var el = event.target;
    if (!(el instanceof HTMLElement) || !el.classList.contains('ui-menu')) return;
    var trigger = el._uiAnchor || menuTrigger(el);
    if (event.newState === 'open') {
      el.setAttribute('role', 'menu');
      menuItems(el).forEach(function(item) {
        item.setAttribute('role', 'menuitem');
        item.tabIndex = -1;
      });
      if (el._uiPoint) {
        var f = el.getBoundingClientRect();
        var vw = document.documentElement.clientWidth;
        var vh = document.documentElement.clientHeight;
        el.style.left = Math.max(8, Math.min(el._uiPoint.x, vw - f.width - 8)) + 'px';
        el.style.top = Math.max(8, Math.min(el._uiPoint.y, vh - f.height - 8)) + 'px';
        el._uiPoint = null;
      } else if (trigger) {
        placeNear(el, trigger, { alignEnd: el.hasAttribute('data-ui-align-end') });
      }
      if (trigger) trigger.setAttribute('aria-expanded', 'true');
      var first = menuItems(el)[0];
      if (first) first.focus();
    } else {
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
      el._uiAnchor = null;
    }
  }, true);

  document.addEventListener('keydown', function(event) {
    var el = event.target.closest ? event.target.closest('.ui-menu') : null;
    if (!el) return;
    var items = menuItems(el);
    if (!items.length) return;
    var index = items.indexOf(document.activeElement);
    var next = null;
    if (event.key === 'ArrowDown') next = items[(index + 1) % items.length];
    else if (event.key === 'ArrowUp') next = items[(index - 1 + items.length) % items.length];
    else if (event.key === 'Home') next = items[0];
    else if (event.key === 'End') next = items[items.length - 1];
    if (next) {
      event.preventDefault();
      next.focus();
    }
  });

  document.addEventListener('click', function(event) {
    var item = event.target.closest('.ui-menu .ui-menu-item');
    if (!item || item.hasAttribute('data-ui-keep-open')) return;
    menu.close(item.closest('.ui-menu'));
  });

  window.addEventListener('scroll', function(event) {
    document.querySelectorAll('.ui-menu:popover-open').forEach(function(el) {
      if (event.target instanceof Node && el.contains(event.target)) return;
      el.hidePopover();
    });
    hideTooltip();
  }, true);

  window.addEventListener('resize', function() {
    document.querySelectorAll('.ui-menu:popover-open').forEach(function(el) {
      el.hidePopover();
    });
  });

  var toastTypes = { success: 'success', error: 'error', danger: 'error', warning: 'warning', info: 'info' };
  var toastTitles = { success: 'Success', error: 'Error', warning: 'Warning', info: 'Notification' };

  function toastRegion() {
    var region = document.getElementById('uiToasts');
    if (!region) {
      region = document.createElement('div');
      region.id = 'uiToasts';
      region.className = 'ui-toasts';
      region.setAttribute('role', 'region');
      region.setAttribute('aria-label', 'Notifications');
      document.body.appendChild(region);
    }
    return region;
  }

  function dismissToast(el) {
    if (!el || el._uiLeaving) return;
    el._uiLeaving = true;
    clearTimeout(el._uiTimer);
    el.classList.add('is-leaving');
    setTimeout(function() {
      el.remove();
    }, 200);
  }

  function toast(message, options) {
    options = options || {};
    var type = toastTypes[options.type] || 'info';
    var el = document.createElement('div');
    el.className = 'ui-toast ui-toast-' + type;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');

    var title = document.createElement('div');
    title.className = 'ui-toast-title';
    title.textContent = options.title || toastTitles[type];

    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'ui-toast-close';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.innerHTML = '<svg class="ic" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8"/></svg>';
    close.addEventListener('click', function() {
      dismissToast(el);
    });

    var body = document.createElement('div');
    body.className = 'ui-toast-message';
    body.textContent = message === null || message === undefined ? '' : String(message);

    el.appendChild(title);
    el.appendChild(close);
    el.appendChild(body);

    var region = toastRegion();
    region.appendChild(el);
    while (region.children.length > 4) region.firstElementChild.remove();

    var duration = options.duration !== undefined ? options.duration : (type === 'error' ? 8000 : 5000);
    function arm() {
      if (duration > 0) el._uiTimer = setTimeout(function() { dismissToast(el); }, duration);
    }
    el.addEventListener('mouseenter', function() { clearTimeout(el._uiTimer); });
    el.addEventListener('mouseleave', arm);
    arm();
    return el;
  }

  function tabsOf(list) {
    return Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
  }

  function selectTab(tab, focus) {
    var list = tab.closest('[data-ui-tabs]');
    if (!list) return;
    tabsOf(list).forEach(function(other) {
      var selected = other === tab;
      other.setAttribute('aria-selected', selected ? 'true' : 'false');
      other.tabIndex = selected ? 0 : -1;
      var panel = document.getElementById(other.getAttribute('aria-controls') || '');
      if (panel) panel.hidden = !selected;
    });
    if (focus) tab.focus();
    tab.dispatchEvent(new CustomEvent('ui:tab', { bubbles: true, detail: { panel: tab.getAttribute('aria-controls') } }));
  }

  function initTabs(root) {
    (root || document).querySelectorAll('[data-ui-tabs]').forEach(function(list) {
      list.setAttribute('role', 'tablist');
      var tabs = tabsOf(list);
      var current = tabs.filter(function(tab) { return tab.getAttribute('aria-selected') === 'true'; })[0] || tabs[0];
      tabs.forEach(function(tab) {
        var selected = tab === current;
        tab.setAttribute('aria-selected', selected ? 'true' : 'false');
        tab.tabIndex = selected ? 0 : -1;
        var panel = document.getElementById(tab.getAttribute('aria-controls') || '');
        if (panel) {
          panel.setAttribute('role', 'tabpanel');
          panel.hidden = !selected;
        }
      });
    });
  }

  document.addEventListener('click', function(event) {
    var tab = event.target.closest('[data-ui-tabs] [role="tab"]');
    if (tab) selectTab(tab, false);
  });

  document.addEventListener('keydown', function(event) {
    var tab = event.target.closest ? event.target.closest('[data-ui-tabs] [role="tab"]') : null;
    if (!tab) return;
    var tabs = tabsOf(tab.closest('[data-ui-tabs]'));
    var index = tabs.indexOf(tab);
    var next = null;
    if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
    else if (event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
    else if (event.key === 'Home') next = tabs[0];
    else if (event.key === 'End') next = tabs[tabs.length - 1];
    if (next) {
      event.preventDefault();
      selectTab(next, true);
    }
  });

  var collapse = {
    set: function(target, expanded) {
      var el = resolve(target);
      if (!el) return;
      el.hidden = !expanded;
      if (el.id) {
        document.querySelectorAll('[data-ui-collapse="#' + CSS.escape(el.id) + '"]').forEach(function(trigger) {
          trigger.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        });
      }
      el.dispatchEvent(new CustomEvent('ui:collapse', { bubbles: true, detail: { expanded: expanded } }));
    },
    toggle: function(target) {
      var el = resolve(target);
      if (el) collapse.set(el, el.hidden);
    }
  };

  function initCollapse(root) {
    (root || document).querySelectorAll('[data-ui-collapse]').forEach(function(trigger) {
      var el = resolve(trigger.getAttribute('data-ui-collapse'));
      if (!el) return;
      trigger.setAttribute('aria-controls', el.id);
      trigger.setAttribute('aria-expanded', el.hidden ? 'false' : 'true');
    });
  }

  document.addEventListener('click', function(event) {
    var trigger = event.target.closest('[data-ui-collapse]');
    if (!trigger) return;
    event.preventDefault();
    collapse.toggle(trigger.getAttribute('data-ui-collapse'));
  });

  var tooltipEl = null;
  var tooltipOwner = null;

  function showTooltip(owner) {
    var text = owner.getAttribute('data-ui-tip');
    if (!text) return;
    if (!tooltipEl) {
      tooltipEl = document.createElement('div');
      tooltipEl.className = 'ui-tooltip';
      tooltipEl.id = 'uiTooltip';
      tooltipEl.setAttribute('role', 'tooltip');
      document.body.appendChild(tooltipEl);
    }
    tooltipOwner = owner;
    tooltipEl.textContent = text;
    tooltipEl.hidden = false;
    owner.setAttribute('aria-describedby', 'uiTooltip');
    placeNear(tooltipEl, owner, { center: true, above: owner.getAttribute('data-ui-tip-side') !== 'bottom' });
  }

  function hideTooltip() {
    if (!tooltipEl || !tooltipOwner) return;
    tooltipOwner.removeAttribute('aria-describedby');
    tooltipOwner = null;
    tooltipEl.hidden = true;
  }

  document.addEventListener('mouseover', function(event) {
    var owner = event.target.closest ? event.target.closest('[data-ui-tip]') : null;
    if (owner && owner !== tooltipOwner) showTooltip(owner);
  });

  document.addEventListener('mouseout', function(event) {
    if (!tooltipOwner) return;
    if (event.relatedTarget instanceof Node && tooltipOwner.contains(event.relatedTarget)) return;
    hideTooltip();
  });

  document.addEventListener('focusin', function(event) {
    var owner = event.target.closest ? event.target.closest('[data-ui-tip]') : null;
    if (owner && owner.matches(':focus-visible')) showTooltip(owner);
  });

  document.addEventListener('focusout', hideTooltip);

  document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') hideTooltip();
  });

  function init(root) {
    initTabs(root);
    initCollapse(root);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { init(document); });
  } else {
    init(document);
  }

  return {
    dialog: dialog,
    menu: menu,
    toast: toast,
    dismissToast: dismissToast,
    tabs: { select: function(target) { var tab = resolve(target); if (tab) selectTab(tab, false); } },
    collapse: collapse,
    tooltip: { show: function(target) { var el = resolve(target); if (el) showTooltip(el); }, hide: hideTooltip },
    init: init
  };
})();

window.showToast = function(message, title, type) {
  var kind = type || 'info';
  var isError = kind === 'error' || kind === 'danger';
  var heading = title && title !== 'Notification' ? title : (isError ? 'Error' : '');
  return window.UI.toast(message, { title: heading, type: kind });
};
