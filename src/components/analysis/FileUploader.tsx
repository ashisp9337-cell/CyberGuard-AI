import { useRef, useState } from "react";
import { ICONS } from "@/lib/icons";
import { formatBytes, cn } from "@/lib/utils";
import type { UploadedFileMeta } from "@/types";

export function FileUploader({
  accepted,
  maxSizeMb = 50,
  file,
  onSelect,
  onRemove,
  error,
}: {
  accepted?: string[];
  maxSizeMb?: number;
  file: UploadedFileMeta | null;
  onSelect: (file: File) => void;
  onRemove: () => void;
  error?: string;
}) {
  const [dragActive, setDragActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function handleFiles(files: FileList | null) {
    if (!files || files.length === 0) return;
    onSelect(files[0]);
  }

  if (file) {
    return (
      <div className="rounded-xl border border-strong bg-elevated p-4 flex items-center gap-3">
        <div className="h-11 w-11 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
          <ICONS.fileWarning size={20} className="text-cyan-400" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-white truncate">{file.name}</p>
          <p className="text-xs text-slate-500 mt-0.5">
            {formatBytes(file.size)} &middot; {file.type || "Unknown type"}
          </p>
          {file.progress < 100 && (
            <div className="mt-2 h-1.5 w-full rounded-full bg-canvas overflow-hidden">
              <div className="h-full bg-cyan-500 rounded-full transition-all" style={{ width: `${file.progress}%` }} />
            </div>
          )}
        </div>
        <button
          onClick={onRemove}
          aria-label="Remove file"
          className="text-slate-500 hover:text-red-400 focus-ring rounded p-1.5 shrink-0"
        >
          <ICONS.trash size={16} />
        </button>
      </div>
    );
  }

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          handleFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        aria-label="Drag and drop a file here, or browse to select one"
        className={cn(
          "rounded-xl border-2 border-dashed p-8 text-center cursor-pointer transition-colors focus-ring",
          dragActive ? "border-cyan-400 bg-cyan-500/5" : error ? "border-red-500/50" : "border-strong hover:border-slate-500 bg-elevated/50"
        )}
      >
        <input
          ref={inputRef}
          type="file"
          className="sr-only"
          accept={accepted?.join(",")}
          onChange={(e) => handleFiles(e.target.files)}
        />
        <div className="mx-auto h-12 w-12 rounded-full bg-cyan-500/10 flex items-center justify-center mb-3">
          <ICONS.upload size={22} className="text-cyan-400" />
        </div>
        <p className="text-sm font-semibold text-white">Drag &amp; drop file here</p>
        <p className="text-xs text-slate-500 mt-1">or click to browse</p>
        <p className="text-[11px] text-slate-600 mt-3">
          {accepted?.length ? `Supported: ${accepted.join(", ")}` : "All file types supported"} &middot; Max {maxSizeMb}MB
        </p>
      </div>
      {error && (
        <p className="text-xs text-red-400 mt-1.5" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
