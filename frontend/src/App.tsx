import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { useAuth } from "./lib/auth";
import Login from "./pages/Login";

const Overview = lazy(() => import("./pages/Overview"));
const Workbench = lazy(() => import("./pages/Workbench"));
const Flows = lazy(() => import("./pages/Flows"));
const Findings = lazy(() => import("./pages/Findings"));
const Console = lazy(() => import("./pages/Console"));
const Missions = lazy(() => import("./pages/Missions"));
const F5 = lazy(() => import("./pages/F5"));
const Reports = lazy(() => import("./pages/Reports"));
const Audit = lazy(() => import("./pages/Audit"));
const Help = lazy(() => import("./pages/Help"));

export default function App() {
  const { me, loading, can } = useAuth();
  if (loading) return <Spinner label="Signing in" />;
  if (!me) return <Login />;
  return (
    <BrowserRouter>
      <Suspense fallback={<Spinner />}>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="workbench" element={<Workbench />} />
            <Route path="flows" element={<Flows />} />
            <Route path="findings" element={<Findings />} />
            <Route path="console" element={<Console />} />
            <Route path="missions" element={<Missions />} />
            <Route path="f5" element={<F5 />} />
            <Route path="reports" element={<Reports />} />
            <Route path="audit" element={can("audit:read") ? <Audit /> : <Navigate to="/" replace />} />
            <Route path="help" element={<Help />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
