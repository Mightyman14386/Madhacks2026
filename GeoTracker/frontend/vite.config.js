import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The backend's CORS allows exactly http://localhost:5173, so pin host and port.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "localhost",
    port: 5173,
    strictPort: true,
  },
});
