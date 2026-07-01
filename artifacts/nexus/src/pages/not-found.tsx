import { AlertCircle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#080808]">
      <div className="w-full max-w-md mx-4 bg-[#0e0e0e] border border-zinc-800 p-6 font-mono"
        style={{ boxShadow: "0 0 0 1px rgba(255,255,255,.03)" }}>
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="h-6 w-6 text-red-500 shrink-0" />
          <h1
            className="text-red-500 font-black text-xl tracking-[.18em] uppercase"
            style={{ textShadow: "0 0 24px rgba(220,38,38,.45)" }}
          >
            404 — NOT FOUND
          </h1>
        </div>
        <p className="text-[11px] text-zinc-500 leading-relaxed">
          The requested route does not exist.{" "}
          <span className="text-zinc-600">Did you forget to add the page to the router?</span>
        </p>
        <button
          onClick={() => history.back()}
          className="mt-5 w-full py-2 border border-zinc-800 text-zinc-500 text-[10px] uppercase tracking-[.25em] hover:border-red-900 hover:text-red-400 transition-colors"
        >
          ← Go Back
        </button>
      </div>
    </div>
  );
}
