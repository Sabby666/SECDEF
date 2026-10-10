import React from "react";
import { AlertTriangle } from "lucide-react";

export interface ErrorAlertProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({
  title = "Backend Error",
  message,
  onRetry
}) => {
  return (
    <div className="p-4 bg-red-950/40 border border-red-800/80 rounded-lg text-red-200 flex items-start gap-3 my-4">
      <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
      <div className="flex-1 text-xs">
        <div className="font-semibold text-red-300 text-sm">{title}</div>
        <div className="mt-1 font-mono break-all">{message}</div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-2 text-xs font-semibold text-red-400 hover:text-red-200 underline cursor-pointer"
          >
            Try Again
          </button>
        )}
      </div>
    </div>
  );
};
