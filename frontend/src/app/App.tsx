import { Link, Navigate, Route, Routes } from 'react-router';
import { PoliciesPage } from '../features/policies/PoliciesPage';
import { AppLayout } from './AppLayout';
import { ScansPage } from '../features/scans/ScansPage';
import { ScanDetailsPage } from '../features/scans/ScanDetailsPage';
export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Navigate to="/scans" replace />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/:scanId" element={<ScanDetailsPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route
          path="*"
          element={
            <section>
              <h1>Page not found</h1>
              <p className="page-description">
                This address does not match a workspace.
              </p>
              <Link to="/scans">Go to scans</Link>
            </section>
          }
        />
      </Route>
    </Routes>
  );
}
