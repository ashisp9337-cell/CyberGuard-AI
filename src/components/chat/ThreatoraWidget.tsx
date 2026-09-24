import { useEffect, useRef, useState, useCallback } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { sendChatMessage, resetChat } from "@/services/api/chatService";
import { ApiError } from "@/services/api/client";
import { ICONS } from "@/lib/icons";

interface ChatMsg {
  id: string;
  role: "user" | "assistant";
  text: string;
  time: number;
}

const WELCOME: ChatMsg = {
  id: "welcome",
  role: "assistant",
  time: Date.now(),
  text: "Hi, I'm **Threatora** — your CyberGuard security assistant. Ask me about phishing, deepfakes, account security, or how any part of this platform works.",
};

const POSITION_KEY = "cyberguard.threatora.position.v1";
const LAUNCHER_SIZE = 56;
const MARGIN = 12;

interface Pos {
  right: number;
  bottom: number;
}

function loadPosition(): Pos {
  try {
    const raw = localStorage.getItem(POSITION_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    // ignore malformed storage
  }
  return { right: 20, bottom: 20 };
}

function clampPosition(pos: Pos): Pos {
  const maxRight = window.innerWidth - LAUNCHER_SIZE - MARGIN;
  const maxBottom = window.innerHeight - LAUNCHER_SIZE - MARGIN;
  return {
    right: Math.min(Math.max(pos.right, MARGIN), Math.max(maxRight, MARGIN)),
    bottom: Math.min(Math.max(pos.bottom, MARGIN), Math.max(maxBottom, MARGIN)),
  };
}

/** Minimal, dependency-free rendering for the light markdown Gemini tends to
 * return: **bold**, "- " / "1. " list lines, and paragraph breaks. Anything
 * unrecognized is shown as plain text — never raw asterisks left visible. */
function renderInline(text: string, keyPrefix: string) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) =>
    part.startsWith("**") && part.endsWith("**") ? (
      <strong key={`${keyPrefix}-${i}`} className="font-semibold text-white">{part.slice(2, -2)}</strong>
    ) : (
      <span key={`${keyPrefix}-${i}`}>{part}</span>
    )
  );
}

function MessageBody({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="space-y-1.5">
      {lines.map((line, idx) => {
        const bullet = /^\s*[-*]\s+/.test(line);
        const numbered = /^\s*\d+\.\s+/.test(line);
        if (bullet || numbered) {
          const content = line.replace(/^\s*([-*]|\d+\.)\s+/, "");
          return (
            <div key={idx} className="flex gap-1.5 pl-0.5">
              <span className="text-cyan-400 shrink-0">{numbered ? line.match(/^\s*(\d+)\./)?.[1] + "." : "•"}</span>
              <span>{renderInline(content, `l${idx}`)}</span>
            </div>
          );
        }
        if (!line.trim()) return <div key={idx} className="h-1.5" />;
        return <div key={idx}>{renderInline(line, `l${idx}`)}</div>;
      })}
    </div>
  );
}

function formatTime(ts: number) {
  return new Date(ts).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

function TypingDots() {
  return (
    <div className="flex items-center gap-1 px-1 py-1">
      {[0, 1, 2].map((i) => (
        <motion.span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-slate-500"
          animate={{ opacity: [0.3, 1, 0.3], y: [0, -3, 0] }}
          transition={{ duration: 0.9, repeat: Infinity, delay: i * 0.15 }}
        />
      ))}
    </div>
  );
}

export function ThreatoraWidget() {
  const { isAuthenticated } = useAuth();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMsg[]>([WELCOME]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pos, setPos] = useState<Pos>(() => clampPosition(loadPosition()));
  const scrollRef = useRef<HTMLDivElement>(null);
  const dragInfo = useRef<{ startX: number; startY: number; startPos: Pos; moved: boolean } | null>(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, open]);

  useEffect(() => {
    const onResize = () => setPos((p) => clampPosition(p));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    dragInfo.current = { startX: e.clientX, startY: e.clientY, startPos: pos, moved: false };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, [pos]);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragInfo.current) return;
    const dx = e.clientX - dragInfo.current.startX;
    const dy = e.clientY - dragInfo.current.startY;
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) {
      dragInfo.current.moved = true;
      setDragging(true);
    }
    if (dragInfo.current.moved) {
      const next = clampPosition({
        right: dragInfo.current.startPos.right - dx,
        bottom: dragInfo.current.startPos.bottom - dy,
      });
      setPos(next);
    }
  }, []);

  const onPointerUp = useCallback(() => {
    if (dragInfo.current?.moved) {
      localStorage.setItem(POSITION_KEY, JSON.stringify(pos));
      setTimeout(() => setDragging(false), 0);
    } else {
      setOpen((v) => !v);
    }
    dragInfo.current = null;
  }, [pos]);

  async function handleSend() {
    const text = input.trim();
    if (!text || sending) return;
    setMessages((prev) => [...prev, { id: `u_${Date.now()}`, role: "user", text, time: Date.now() }]);
    setInput("");
    setSending(true);
    setError(null);
    try {
      const reply = await sendChatMessage(text);
      setMessages((prev) => [...prev, { id: `a_${Date.now()}`, role: "assistant", text: reply, time: Date.now() }]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't reach Threatora. Please try again.");
    } finally {
      setSending(false);
    }
  }

  async function handleClear() {
    setMessages([WELCOME]);
    setError(null);
    try {
      await resetChat();
    } catch {
      // Non-fatal — next message just starts a fresh session server-side.
    }
  }

  // Panel opens toward whichever side of the screen has more room, so it
  // never gets clipped off-screen no matter where the launcher was dragged.
  const openLeftward = pos.right < window.innerWidth / 2;
  const openUpward = pos.bottom < window.innerHeight / 2;

  return createPortal(
    <>
      <motion.button
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        style={{ right: pos.right, bottom: pos.bottom, touchAction: "none" }}
        aria-label={open ? "Close Threatora" : "Open Threatora"}
        className={`fixed z-[60] h-14 w-14 rounded-full flex items-center justify-center focus-ring select-none ${
          dragging ? "cursor-grabbing" : "cursor-pointer"
        } bg-gradient-to-br from-cyan-400 to-blue-600 shadow-xl shadow-cyan-500/30`}
        whileHover={{ scale: dragging ? 1 : 1.06 }}
      >
        {!open && (
          <motion.span
            className="absolute inset-0 rounded-full bg-cyan-400"
            animate={{ scale: [1, 1.4, 1], opacity: [0.5, 0, 0.5] }}
            transition={{ duration: 2.2, repeat: Infinity }}
          />
        )}
        <span className="relative">{open ? <ICONS.close size={22} className="text-white" /> : <ICONS.brain size={24} className="text-white" />}</span>
      </motion.button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ duration: 0.18 }}
            style={{
              right: openLeftward ? "auto" : Math.max(pos.right, MARGIN),
              left: openLeftward ? Math.max(window.innerWidth - pos.right - 384, MARGIN) : "auto",
              bottom: openUpward ? "auto" : pos.bottom + LAUNCHER_SIZE + 10,
              top: openUpward ? Math.max(window.innerHeight - pos.bottom - LAUNCHER_SIZE - 10 - 520, MARGIN) : "auto",
            }}
            className="fixed z-[60] w-[calc(100vw-2.5rem)] max-w-sm h-[520px] max-h-[70vh] rounded-2xl border border-strong bg-elevated shadow-2xl flex flex-col overflow-hidden"
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-default shrink-0 bg-gradient-to-r from-cyan-500/10 to-transparent">
              <div className="flex items-center gap-2.5">
                <div className="h-8 w-8 rounded-full bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shrink-0">
                  <ICONS.brain size={16} className="text-white" />
                </div>
                <div>
                  <p className="text-sm font-bold text-white leading-tight flex items-center gap-1.5">
                    Threatora
                    <span className="text-[9px] font-semibold uppercase tracking-wide bg-cyan-500/15 text-cyan-300 px-1.5 py-0.5 rounded-full">AI</span>
                  </p>
                  <p className="text-[11px] text-slate-500 leading-tight">Your security assistant</p>
                </div>
              </div>
              <button onClick={handleClear} className="text-slate-500 hover:text-white p-1.5 rounded-md hover:bg-canvas focus-ring" aria-label="Clear conversation">
                <ICONS.refresh size={15} />
              </button>
            </div>

            {!isAuthenticated ? (
              <div className="flex-1 flex flex-col items-center justify-center gap-3 px-6 text-center">
                <div className="h-12 w-12 rounded-full bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
                  <ICONS.brain size={22} className="text-white" />
                </div>
                <p className="text-sm text-slate-300">Sign in to chat with Threatora, your CyberGuard security assistant.</p>
                <Link to="/signin" className="rounded-lg bg-cyan-500 text-slate-950 font-medium px-4 py-2 text-sm hover:bg-cyan-400 focus-ring">
                  Sign in
                </Link>
              </div>
            ) : (
              <>
                <div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
                  {messages.map((m) => (
                    <div key={m.id} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                      <div className={`max-w-[85%] ${m.role === "user" ? "items-end" : "items-start"} flex flex-col gap-0.5`}>
                        <div
                          className={`rounded-xl px-3 py-2 text-sm leading-relaxed ${
                            m.role === "user" ? "bg-cyan-500 text-slate-950" : "bg-canvas text-slate-200 border border-default"
                          }`}
                        >
                          {m.role === "assistant" ? <MessageBody text={m.text} /> : m.text}
                        </div>
                        <span className="text-[10px] text-slate-600 px-1">{formatTime(m.time)}</span>
                      </div>
                    </div>
                  ))}
                  {sending && (
                    <div className="flex justify-start">
                      <div className="bg-canvas border border-default rounded-xl"><TypingDots /></div>
                    </div>
                  )}
                  {error && (
                    <div className="flex justify-start">
                      <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2 text-xs text-red-300">{error}</div>
                    </div>
                  )}
                </div>

                <div className="p-2.5 border-t border-default shrink-0 flex items-center gap-2">
                  <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), handleSend())}
                    placeholder="Ask Threatora a security question…"
                    disabled={sending}
                    className="flex-1 rounded-lg bg-canvas border border-strong px-3 py-2 text-sm text-white placeholder:text-slate-600 focus-ring disabled:opacity-50"
                  />
                  <button
                    onClick={handleSend}
                    disabled={sending || !input.trim()}
                    aria-label="Send message"
                    className="h-9 w-9 shrink-0 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 text-white flex items-center justify-center hover:opacity-90 focus-ring disabled:opacity-40"
                  >
                    <ICONS.send size={15} />
                  </button>
                </div>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </>,
    document.body
  );
}