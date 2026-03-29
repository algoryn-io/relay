import MetricsChart from "./components/MetricsChart.jsx";
import RequestsTable from "./components/RequestsTable.jsx";
import BackendStatus from "./components/BackendStatus.jsx";
import RateLimitPanel from "./components/RateLimitPanel.jsx";
import ErrorsPanel from "./components/ErrorsPanel.jsx";

export default function App() {
  return (
    <main style={{ padding: "1rem", display: "grid", gap: "1rem" }}>
      <h1>Relay Dashboard</h1>
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
        <MetricsChart />
        <BackendStatus />
      </section>
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
        <RateLimitPanel />
        <ErrorsPanel />
      </section>
      <RequestsTable />
    </main>
  );
}
