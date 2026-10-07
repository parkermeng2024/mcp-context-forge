export function mainLayout() {
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
      this.$watch('sidebarCollapsed', function (val) {
        try {
          localStorage.setItem('sidebarCollapsed', String(val));
        } catch (e) {
          if (window.Admin) window.Admin.logRestrictedContext(e);
        }
      });
      const self = this;
      window.addEventListener('resize', function () {
        self.isDesktop = window.innerWidth >= 1024;
        if (window.innerWidth >= 1024) self.sidebarOpen = true;
      });
    },
  };
}
