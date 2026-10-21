// Lets any page open Threatora (the chat widget) with a question, e.g. "Ask Threatora about this scan".
export const THREATORA_EVENT = "threatora:ask";

export interface ThreatoraAsk {
  message: string;
  /** true: send it right away; false: only put it in the input box for the user to finish */
  send?: boolean;
}

export function askThreatora(message: string, send = true) {
  window.dispatchEvent(new CustomEvent<ThreatoraAsk>(THREATORA_EVENT, { detail: { message, send } }));
}
