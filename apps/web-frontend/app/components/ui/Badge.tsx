import React from "react";
import clsx from "clsx";
import { AlertTriangle, ShieldAlert, AlertCircle, Info, CheckCircle2, RotateCcw, HelpCircle } from "lucide-react";

export type BadgeVariant = 
  | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  | "open" | "acknowledged" | "in_progress" | "resolved" | "reopened" | "unknown"
  | "verified" | "pending_verification" | "failed" | "expired"
  | "completed" | "active" | "removed" | "archived"
  | "RESOLVED" | "STILL_PRESENT" | "INCOMPLETE" | "UNVERIFIED"
  | "expected" | "unexpected";

export interface BadgeProps {
  variant: BadgeVariant | string;
  label?: string;
  children?: React.ReactNode;
  size?: "sm" | "md";
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  variant,
  label,
  children,
  size = "md",
  className
}) => {
  const norm = (variant || "").toString().toUpperCase();

  let colorClasses = "badge-info";
  let IconComponent: React.ComponentType<{ className?: string }> = Info;

  if (norm === "CRITICAL" || norm === "STILL_PRESENT") {
    colorClasses = "badge-critical";
    IconComponent = ShieldAlert;
  } else if (norm === "HIGH" || norm === "UNEXPECTED" || norm === "FAILED") {
    colorClasses = "badge-high";
    IconComponent = AlertTriangle;
  } else if (norm === "MEDIUM" || norm === "OPEN" || norm === "IN_PROGRESS" || norm === "INCOMPLETE") {
    colorClasses = "badge-medium";
    IconComponent = AlertCircle;
  } else if (norm === "LOW" || norm === "ACKNOWLEDGED" || norm === "PENDING_VERIFICATION") {
    colorClasses = "badge-low";
    IconComponent = Info;
  } else if (norm === "RESOLVED" || norm === "VERIFIED" || norm === "COMPLETED" || norm === "ACTIVE" || norm === "EXPECTED") {
    colorClasses = "badge-success";
    IconComponent = CheckCircle2;
  } else if (norm === "REOPENED") {
    colorClasses = "badge-high";
    IconComponent = RotateCcw;
  } else if (norm === "UNKNOWN" || norm === "UNVERIFIED") {
    colorClasses = "badge-info";
    IconComponent = HelpCircle;
  }

  const displayText = children || label || variant;
  const sizeStyles = size === "sm" ? "px-1.5 py-0.5 text-[10.5px]" : "px-2 py-0.5 text-[11.5px]";

  return (
    <span className={clsx("asm-badge", colorClasses, sizeStyles, className)}>
      <IconComponent className={size === "sm" ? "w-3 h-3" : "w-3.5 h-3.5"} />
      <span>{displayText}</span>
    </span>
  );
};

export default Badge;

