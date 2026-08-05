import "./App.css";
import { useEffect, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "../convex/_generated/api";
import { authClient } from "./authClient.js";

function AuthCallback() {
  useEffect(() => {
    const result = authClient.handleAuthCallback();
    if (result.error !== null) {
      console.warn("Sign-in failed:", result.error);
    }
    window.location.replace(result.redirect);
  }, []);
  return <p>Signing in…</p>;
}

function Notes() {
  const { isAuthenticated, isLoading, signIn, signOut } =
    authClient.useGoogleAuth();
  const claim = authClient.useAnonymousClaim();
  // A verified Google identity always wins server-side; suppressing the
  // claim once signed in just avoids sending a useless credential.
  const anonymousClaim = isAuthenticated ? undefined : (claim ?? undefined);

  const ensureProfile = useMutation(api.example.ensureProfile);
  const profile = useQuery(api.example.currentProfile, { anonymousClaim });
  const notes = useQuery(api.example.listMyNotes, { anonymousClaim });
  const addNote = useMutation(api.example.addNote);
  const removeNote = useMutation(api.example.removeNote);
  const [text, setText] = useState("");

  useEffect(() => {
    if (isLoading) return;
    // Pass the claim even when signed in so a pre-sign-in anonymous
    // profile is upgraded/merged, then retire it client-side too.
    void ensureProfile({ anonymousClaim: claim ?? undefined }).then(() => {
      if (isAuthenticated) authClient.clearAnonymousClaim();
    });
  }, [ensureProfile, claim, isAuthenticated, isLoading]);

  return (
    <div className="card">
      <p>
        {profile === undefined
          ? "Loading…"
          : profile === null
            ? "No profile yet"
            : `Hello, ${profile.displayName}${profile.isAnonymous ? " (anonymous)" : ""}`}
      </p>
      {isAuthenticated ? (
        <button onClick={() => signOut()}>Sign out</button>
      ) : (
        <button onClick={() => signIn()}>Sign in with Google</button>
      )}
      <div style={{ marginTop: "1rem" }}>
        <input
          type="text"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Write a note"
        />
        <button
          onClick={() => {
            if (text.trim()) {
              void addNote({ text, anonymousClaim });
              setText("");
            }
          }}
        >
          Add note
        </button>
      </div>
      <ul>
        {notes?.map((note) => (
          <li key={note._id}>
            {note.text}{" "}
            <button
              onClick={() => void removeNote({ noteId: note._id, anonymousClaim })}
            >
              ✕
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function App() {
  if (window.location.pathname === "/auth/callback") {
    return <AuthCallback />;
  }
  return (
    <>
      <h1>convex-googly-auth example</h1>
      <Notes />
    </>
  );
}

export default App;
