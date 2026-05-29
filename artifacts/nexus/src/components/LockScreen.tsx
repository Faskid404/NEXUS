import React, { useState } from "react";

export default function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (password === "omowoli12345@") {
      onUnlock();
    } else {
      setError(true);
      setPassword("");
    }
  };

  return (
    <div className="min-h-screen w-full flex flex-col items-center justify-center bg-black text-red-600 font-mono">
      <div className="w-full max-w-md p-8 border border-red-900 bg-zinc-950">
        <h1 className="text-4xl font-bold mb-8 text-center tracking-widest text-red-600">NEXUSFORGE</h1>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm mb-2 text-zinc-400">ENTER AUTHORIZATION KEY:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setError(false);
              }}
              className="w-full bg-black border border-red-900 px-4 py-3 text-red-600 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 transition-colors"
              autoFocus
            />
          </div>
          {error && <div className="text-red-500 text-sm font-bold">Access Denied</div>}
          <button
            type="submit"
            className="w-full bg-red-950 text-red-500 border border-red-900 py-3 font-bold hover:bg-red-900 hover:text-red-400 transition-colors"
          >
            UNLOCK
          </button>
        </form>
      </div>
    </div>
  );
}
