import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { ICONS } from "@/lib/icons";

/** (10 Nov) Reverse image search: find where a picture (or a video frame) appeared before - the fastest proof that a
 *  "new" photo is old, taken from someone else, or edited. Nothing is sent anywhere by this card: the picture is only
 *  copied to YOUR clipboard / saved, and the search site opens empty; you paste or drop the picture there yourself. */
const SITES = [
  { name: "Google Lens", url: "https://images.google.com/", how: "click the camera icon, then paste (Ctrl+V) or drop the picture" },
  { name: "Bing Visual Search", url: "https://www.bing.com/visualsearch", how: "paste (Ctrl+V) or drop the picture" },
  { name: "TinEye", url: "https://tineye.com/", how: "paste (Ctrl+V) or upload the saved picture - shows the OLDEST copy online" },
  { name: "Yandex Images", url: "https://yandex.com/images/", how: "click the camera icon, then upload the saved picture - strong for faces" },
];

const BTN = "rounded-lg border px-3 py-1.5 text-xs font-medium focus-ring disabled:opacity-40";

/** A PNG of the picture, or of the video's frame at about 1 second. Null when the browser cannot show the file
 *  (e.g. iPhone HEIC in Chrome). */
async function toPng(file: File): Promise<Blob | null> {
  const draw = (src: CanvasImageSource, w: number, h: number) => new Promise<Blob | null>((resolve) => {
    const scale = Math.min(1, 2048 / Math.max(w, h));
    const c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(w * scale));
    c.height = Math.max(1, Math.round(h * scale));
    const ctx = c.getContext("2d");
    if (!ctx) return resolve(null);
    ctx.drawImage(src, 0, 0, c.width, c.height);
    c.toBlob((b) => resolve(b), "image/png");
  });
  if (file.type.startsWith("video/") || /\.(mp4|mov|webm|mkv|m4v|3gp)$/i.test(file.name)) {
    const url = URL.createObjectURL(file);
    try {
      const v = document.createElement("video");
      v.muted = true;
      v.preload = "auto";
      v.src = url;
      await new Promise<void>((ok, bad) => { v.onloadeddata = () => ok(); v.onerror = () => bad(new Error("video")); });
      v.currentTime = Math.min(1, (v.duration || 2) / 2);
      await new Promise<void>((ok) => { v.onseeked = () => ok(); });
      return await draw(v, v.videoWidth, v.videoHeight);
    } catch {
      return null;
    } finally {
      URL.revokeObjectURL(url);
    }
  }
  try {
    const bmp = await createImageBitmap(file);
    return await draw(bmp, bmp.width, bmp.height);
  } catch {
    return null;
  }
}

export function ReverseImageSearchCard({ file }: { file: File }) {
  const { notify } = useToast();
  const [png, setPng] = useState<Blob | null>(null);
  const [ready, setReady] = useState(false);
  const [preview, setPreview] = useState("");
  const isVideo = file.type.startsWith("video/") || /\.(mp4|mov|webm|mkv|m4v|3gp)$/i.test(file.name);

  useEffect(() => {
    let alive = true;
    let url = "";
    toPng(file).then((b) => {
      if (!alive) return;
      setPng(b);
      setReady(true);
      if (b) {
        url = URL.createObjectURL(b);
        setPreview(url);
      }
    });
    return () => { alive = false; if (url) URL.revokeObjectURL(url); };
  }, [file]);

  async function copy() {
    if (!png) return;
    try {
      await navigator.clipboard.write([new ClipboardItem({ "image/png": png })]);
      notify({ variant: "success", title: "Picture copied", description: "Open a search site below and press Ctrl+V." });
    } catch {
      notify({ variant: "warning", title: "Copy not allowed by this browser", description: "Use 'Save picture' and drop the file on the search site instead." });
    }
  }

  function save() {
    if (!png) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(png);
    a.download = `${file.name.replace(/\.[^.]+$/, "") || "picture"}${isVideo ? "_frame" : ""}.png`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  return (
    <Card>
      <CardHeader title="Reverse image search" icon={<ICONS.search size={16} />}
        subtitle={`Find where this ${isVideo ? "video frame" : "picture"} was posted before - an older copy, the real source, or the original before editing is often the quickest proof of a fake.`} />
      <CardBody>
        <div className="flex flex-col md:flex-row gap-4">
          {preview && <img src={preview} alt="The picture to search for" className="h-28 w-auto rounded border border-default object-contain self-start" />}
          <div className="flex-1 space-y-3">
            {!ready ? <p className="text-xs text-slate-500">Preparing the picture…</p> : !png ? (
              <p className="text-xs text-amber-300">This browser cannot show this file (for example an iPhone HEIC photo in Chrome). Open the original photo on your phone and use Google Lens there, or send it as JPG and scan again.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                <button className={`${BTN} border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/10`} onClick={copy}>1. Copy picture</button>
                <button className={`${BTN} border-default text-slate-300 hover:bg-white/5`} onClick={save}>or Save picture (PNG)</button>
              </div>
            )}
            <div>
              <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">2. Open a search site and paste it there</p>
              <ul className="space-y-1">
                {SITES.map((s) => (
                  <li key={s.name} className="text-xs text-slate-400">
                    <a href={s.url} target="_blank" rel="noopener noreferrer" className="text-cyan-300 hover:underline">{s.name}</a> - {s.how}
                  </li>
                ))}
              </ul>
            </div>
            <p className="text-[11px] text-slate-500">CyberGuard sends nothing: the picture goes to a search site only when you paste or drop it there yourself. Do not search private photos of other people.</p>
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
