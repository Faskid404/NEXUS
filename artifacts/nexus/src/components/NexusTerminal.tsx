import React, { useEffect, useRef, useImperativeHandle, forwardRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

export interface NexusTerminalHandle {
  write:     (data: string) => void;
  writeln:   (data: string) => void;
  writeAnsi: (data: string) => void;
  clear:     () => void;
  fit:       () => void;
}

interface Props {
  className?: string;
  onData?:    (data: string) => void;
}

const THEME = {
  background:         "#000000",
  foreground:         "#d4d4d8",
  cursor:             "#ef4444",
  cursorAccent:       "#000000",
  black:              "#18181b",
  red:                "#ef4444",
  green:              "#4ade80",
  yellow:             "#facc15",
  blue:               "#60a5fa",
  magenta:            "#e879f9",
  cyan:               "#22d3ee",
  white:              "#d4d4d8",
  brightBlack:        "#52525b",
  brightRed:          "#f87171",
  brightGreen:        "#86efac",
  brightYellow:       "#fde047",
  brightBlue:         "#93c5fd",
  brightMagenta:      "#f0abfc",
  brightCyan:         "#67e8f9",
  brightWhite:        "#f4f4f5",
  selectionBackground:"#27272a",
};

export function ansiLine(text: string): string {
  if (/EXECUTION CONFIRMED/.test(text))     return `\x1b[1;32m${text}\x1b[0m`;
  if (/POSSIBLE BLIND RCE/.test(text))      return `\x1b[1;33m${text}\x1b[0m`;
  if (/BLIND RCE CONFIRMED/.test(text))     return `\x1b[1;32m${text}\x1b[0m`;
  if (/WAF:/.test(text))                    return `\x1b[33m${text}\x1b[0m`;
  if (/^\[NEXUSFORGE\]/.test(text))         return `\x1b[1;31m${text}\x1b[0m`;
  if (/^\[TARGET\]/.test(text))             return `\x1b[33m${text}\x1b[0m`;
  if (/^\[METHOD\]/.test(text))             return `\x1b[33m${text}\x1b[0m`;
  if (/^\[PARAM\]/.test(text))              return `\x1b[33m${text}\x1b[0m`;
  if (/^\[MODE\]/.test(text))               return `\x1b[35m${text}\x1b[0m`;
  if (/^\[PAYLOAD\]/.test(text))            return `\x1b[36m${text}\x1b[0m`;
  if (/^\[INJECT\]/.test(text))             return `\x1b[34m${text}\x1b[0m`;
  if (/^\[OOB\]/.test(text))               return `\x1b[1;35m${text}\x1b[0m`;
  if (/^\[CONFIRMED\]/.test(text))          return `\x1b[1;32m${text}\x1b[0m`;
  if (/^\[ERROR\]/.test(text))              return `\x1b[31m${text}\x1b[0m`;
  if (/^\[WARN\]/.test(text))               return `\x1b[33m${text}\x1b[0m`;
  if (/^\[OK\]/.test(text))                return `\x1b[32m${text}\x1b[0m`;
  if (/^\[FETCH ERROR\]/.test(text))        return `\x1b[31m${text}\x1b[0m`;
  if (/^\[TIMING\]/.test(text))             return `\x1b[32m${text}\x1b[0m`;
  if (/^\[BOT\]/.test(text))               return `\x1b[33m${text}\x1b[0m`;
  if (/SUCCESS|EXEC|CONFIRMED/.test(text))  return `\x1b[32m${text}\x1b[0m`;
  if (/BLOCKED|WAF|FILTERED/.test(text))    return `\x1b[31m${text}\x1b[0m`;
  if (/SKIP|skip/.test(text))               return `\x1b[90m${text}\x1b[0m`;
  if (/OOB callback|oob_hit/.test(text))    return `\x1b[1;35m${text}\x1b[0m`;
  if (/^  │/.test(text))                    return `\x1b[90m${text}\x1b[0m`;
  if (/^  ┌─ RESPONSE/.test(text))          return `\x1b[36m${text}\x1b[0m`;
  if (/^  └──/.test(text))                  return `\x1b[90m${text}\x1b[0m`;
  if (/^  ├─/.test(text))                   return `\x1b[33m${text}\x1b[0m`;
  return text;
}

const NexusTerminal = forwardRef<NexusTerminalHandle, Props>(function NexusTerminal(
  { className, onData },
  ref,
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef      = useRef<Terminal | null>(null);
  const fitRef       = useRef<FitAddon | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      theme:            THEME,
      fontFamily:       "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Courier New', monospace",
      fontSize:         12,
      lineHeight:       1.35,
      cursorBlink:      true,
      cursorStyle:      "block",
      scrollback:       20000,
      allowProposedApi: true,
      convertEol:       true,
      disableStdin:     false,
      windowsMode:      false,
    });

    const fit   = new FitAddon();
    const links = new WebLinksAddon();
    term.loadAddon(fit);
    term.loadAddon(links);
    term.open(containerRef.current);

    requestAnimationFrame(() => {
      try { fit.fit(); } catch { /**/ }
    });

    if (onData) term.onData(onData);

    termRef.current = term;
    fitRef.current  = fit;

    term.writeln("\x1b[1;31m ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗\x1b[0m");
    term.writeln("\x1b[1;31m ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝\x1b[0m");
    term.writeln("\x1b[1;31m ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗\x1b[0m");
    term.writeln("\x1b[1;31m ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║\x1b[0m");
    term.writeln("\x1b[1;31m ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║\x1b[0m");
    term.writeln("\x1b[1;31m ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝\x1b[0m");
    term.writeln("\x1b[90m ─── Auto-Escalation Engine v2  ─────────────────────────\x1b[0m");
    term.writeln("\x1b[90m Configure parameters on the left panel, then LAUNCH.\x1b[0m");
    term.writeln("");

    const ro = new ResizeObserver(() => {
      requestAnimationFrame(() => {
        try { fit.fit(); } catch { /**/ }
      });
    });
    ro.observe(containerRef.current);

    return () => {
      ro.disconnect();
      term.dispose();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useImperativeHandle(ref, () => ({
    write(data: string) {
      termRef.current?.write(data);
    },
    writeln(data: string) {
      termRef.current?.writeln(ansiLine(data));
    },
    writeAnsi(data: string) {
      termRef.current?.write(data);
    },
    clear() {
      termRef.current?.clear();
      termRef.current?.writeln("\x1b[1;31m NEXUSFORGE\x1b[0m\x1b[90m ─── Auto-Escalation Engine Ready ──────────────────\x1b[0m");
      termRef.current?.writeln("");
    },
    fit() {
      requestAnimationFrame(() => {
        try { fitRef.current?.fit(); } catch { /**/ }
      });
    },
  }));

  return (
    <div
      ref={containerRef}
      className={className}
      style={{ width: "100%", height: "100%", overflow: "hidden" }}
    />
  );
});

export default NexusTerminal;
