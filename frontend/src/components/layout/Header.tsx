"use client";

import React, { useState, useEffect } from "react";
import { RefreshCw } from "lucide-react";
import type { SystemStatus } from "@/types";

interface HeaderProps {
  title: string;
  systemStatus?: SystemStatus;
  onRefresh?: () => void;
}

export default function Header({ title, systemStatus = "Safe", onRefresh }: HeaderProps) {
  const [time, setTime] = useState("");

  useEffect(() => {
    const update = () => {
      setTime(new Date().toLocaleTimeString("en-US", { hour12: false }));
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const statusClass =
    systemStatus === "Critical"
      ? "critical"
      : systemStatus === "Warning"
      ? "warning"
      : "safe";

  return (
    <header className="header">
      <h2 className="header-title">{title}</h2>
      <div className="header-right">
        <span className="header-time">{time}</span>
        <div className={`header-status ${statusClass}`}>
          <div className={`header-dot ${statusClass}`} />
          {systemStatus}
        </div>
        {onRefresh && (
          <button className="btn btn-sm" onClick={onRefresh} title="Refresh data">
            <RefreshCw size={14} />
          </button>
        )}
      </div>
    </header>
  );
}
