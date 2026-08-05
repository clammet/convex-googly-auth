import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexProviderWithAuth, ConvexReactClient } from "convex/react";
import App from "./App.jsx";
import { authClient } from "./authClient.js";
import "./index.css";

const address = import.meta.env.VITE_CONVEX_URL;

const convex = new ConvexReactClient(address);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <authClient.GoogleAuthProvider>
      <ConvexProviderWithAuth
        client={convex}
        useAuth={authClient.useConvexGooglyAuth}
      >
        <App />
      </ConvexProviderWithAuth>
    </authClient.GoogleAuthProvider>
  </StrictMode>,
);
