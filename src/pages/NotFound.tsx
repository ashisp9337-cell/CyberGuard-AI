import { Link } from "react-router-dom";
import { Button } from "@/components/ui/Button";
import { ICONS } from "@/lib/icons";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-canvas flex flex-col items-center justify-center text-center px-4">
      <div className="h-14 w-14 rounded-full bg-red-500/10 flex items-center justify-center mb-4">
        <ICONS.shieldX size={26} className="text-red-400" />
      </div>
      <h1 className="text-xl font-bold text-white">Page Not Found</h1>
      <p className="text-sm text-slate-500 mt-2 max-w-sm">The page you're looking for doesn't exist or may have been moved.</p>
      <div className="flex flex-col sm:flex-row gap-3 mt-6">
        <Link to="/">
          <Button variant="secondary">Go to Homepage</Button>
        </Link>
        <Link to="/dashboard">
          <Button>Open Dashboard</Button>
        </Link>
      </div>
    </div>
  );
}
