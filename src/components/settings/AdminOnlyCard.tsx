import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";

/** Shown instead of a system-wide control when the signed-in account is not the CyberGuard administrator. */
export function AdminOnlyCard({ title, what }: { title: string; what: string }) {
  return (
    <Card className="lg:col-span-2">
      <CardHeader title={title} subtitle={what} icon={<ICONS.lock size={16} />} />
      <CardBody>
        <p className="text-sm text-slate-400">
          Managed by the CyberGuard administrator. Your own scans, incidents and alerts are not affected.
        </p>
      </CardBody>
    </Card>
  );
}
