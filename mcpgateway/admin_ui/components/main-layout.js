export function mainLayout() {
  const boundLinks = new WeakSet();
  let railTooltip = null;

  const removeRailTooltip = () => {
    if (railTooltip) {
      railTooltip.remove();
      railTooltip = null;
    }
  };

  return {
    sidebarOpen: true,
    sidebarCollapsed: false,
    isDesktop: window.innerWidth >= 1024,
    init: function () {
      try {
        this.sidebarCollapsed = JSON.parse(localStorage.getItem('sidebarCollapsed') || 'false');
      } catch (e) {
        if (window.Admin) window.Admin.logRestrictedContext(e);
      }
      const self = this;
      this.$watch('sidebarCollapsed', function (val) {
        try {
          localStorage.setItem('sidebarCollapsed', String(val));
        } catch (e) {
          if (window.Admin) window.Admin.logRestrictedContext(e);
        }
        self.syncNavLabels(val);
      });
      this.syncNavLabels(this.sidebarCollapsed);
      window.addEventListener('resize', function () {
        self.isDesktop = window.innerWidth >= 1024;
        if (window.innerWidth >= 1024) self.sidebarOpen = true;
      });
    },
    /**
     * Mirror each nav link label into aria-label while the rail is collapsed, and
     * bind the hover tooltip once per link. The rail scrolls on both axes, so the
     * tooltip mounts on the body as a fixed element to escape that clipping.
     */
    syncNavLabels: function (collapsed) {
      document.querySelectorAll('.sidebar-link').forEach((link) => {
        const label = link.querySelector('span:not(.sidebar-icon)');
        if (!label) return;
        const text = label.textContent.trim();
        if (collapsed) {
          link.setAttribute('aria-label', text);
          link.dataset.sidebarLabel = text;
        } else {
          link.removeAttribute('aria-label');
          delete link.dataset.sidebarLabel;
          this.hideNavTooltip();
        }
        if (!boundLinks.has(link)) {
          boundLinks.add(link);
          link.addEventListener('mouseenter', () => this.showNavTooltip(link));
          link.addEventListener('mouseleave', () => this.hideNavTooltip());
          link.addEventListener('focus', () => this.showNavTooltip(link));
          link.addEventListener('blur', () => this.hideNavTooltip());
        }
      });
    },
    /**
     * Render the label beside a nav link. A collapsed rail shows icons only, so the
     * tooltip restores the destination name for the pointer.
     */
    showNavTooltip: function (link) {
      if (!this.sidebarCollapsed) return;
      const text = link.dataset.sidebarLabel;
      if (!text) return;
      this.hideNavTooltip();
      const tooltip = document.createElement('div');
      tooltip.className = 'sidebar-rail-tooltip';
      tooltip.setAttribute('role', 'tooltip');
      tooltip.textContent = text;
      document.body.appendChild(tooltip);
      const anchor = link.getBoundingClientRect();
      const rail = link.closest('nav');
      const box = tooltip.getBoundingClientRect();
      const edge = (rail || link).getBoundingClientRect().right;
      tooltip.style.left = `${Math.round(edge + 8)}px`;
      tooltip.style.top = `${Math.round(anchor.top + (anchor.height - box.height) / 2)}px`;
      railTooltip = tooltip;
    },
    hideNavTooltip: function () {
      removeRailTooltip();
    },
  };
}
