import { useEffect, useState } from "react";
import { API_URL, getHealth } from "./api.js";

export default function App() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getHealth()
      .then((h) => { setHealth(h); setError(null); })
      .catch((e) => setError(e.message));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>
      <h1>Geo-Trench</h1>
      {error && <p>Backend not reachable at {API_URL} ({error})</p>}
      {!error && !health && <p>Connecting to {API_URL}…</p>}
      {health && (
        <>
          <p>Connected to backend at {API_URL}</p>
          <pre>{JSON.stringify(health, null, 2)}</pre>
        </>
      )}
    </main>
  );
}
