import React from "react";
import { UserRole } from "../../lib/types";
import { Lock } from "lucide-react";

export interface RBACGateProps {
  requiredRole: "ADMIN" | "MEMBER";
  currentRole: UserRole;
  children: React.ReactNode;
  fallbackMessage?: string;
}

const ROLE_RANK: Record<UserRole, number> = {
  OWNER: 4,
  ADMIN: 3,
  MEMBER: 2,
  VIEWER: 1
};

export const RBACGate: React.FC<RBACGateProps> = ({
  requiredRole,
  currentRole,
  children,
  fallbackMessage
}) => {
  const currentRank = ROLE_RANK[currentRole] || 1;
  const requiredRank = ROLE_RANK[requiredRole] || 2;

  if (currentRank < requiredRank) {
    return (
      <div className="p-3 bg-slate-900/60 border border-slate-800 rounded text-slate-400 text-xs flex items-center gap-2">
        <Lock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span>
          {fallbackMessage || `Requires ${requiredRole}+ role to execute this action. Active role: ${currentRole}`}
        </span>
      </div>
    );
  }

  return <>{children}</>;
};
