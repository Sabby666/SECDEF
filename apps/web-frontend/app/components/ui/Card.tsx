import React from "react";
import clsx from "clsx";

export interface CardProps {
  title?: React.ReactNode;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerClassName?: string;
  style?: React.CSSProperties;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  action,
  children,
  className,
  headerClassName,
  style
}) => {
  return (
    <div className={clsx("asm-card", className)} style={style}>
      {(title || action) && (
        <div className={clsx("asm-card-header", headerClassName)}>
          <div>
            {typeof title === "string" ? (
              <h3 style={{ fontSize: "15px", fontWeight: 600, color: "var(--text-primary)" }}>{title}</h3>
            ) : (
              title
            )}
            {subtitle && <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div>{children}</div>
    </div>
  );
};
