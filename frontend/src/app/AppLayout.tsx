import { NavLink, Outlet } from 'react-router';
export function AppLayout() {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="app-header">
        <span className="brand">
          ContainerGuard
          <span className="brand-dot" aria-hidden="true">
            .
          </span>
        </span>
        <nav aria-label="Main navigation">
          <NavLink to="/scans">Scans</NavLink>
          <NavLink to="/policies">Policies</NavLink>
        </nav>
        <span className="workspace-label">Local workspace</span>
      </header>
      <main id="main-content" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="app-footer">
        Container image scans, evidence, and policy decisions.
      </footer>
    </div>
  );
}
