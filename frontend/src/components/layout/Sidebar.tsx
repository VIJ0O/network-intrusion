"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Activity,
  Network,
  MonitorSmartphone,
  Brain,
  Bell,
  History,
  FileText,
  Terminal,
  Settings,
  Shield,
  ShieldAlert,
} from "lucide-react";

interface NavItem {
  href: string;
  label: string;
  icon: React.ReactNode;
  badge?: number;
}

interface SidebarProps {
  alertCount?: number;
  isConnected?: boolean;
}

export default function Sidebar({ alertCount = 0, isConnected = false }: SidebarProps) {
  const pathname = usePathname();

  const mainNav: NavItem[] = [
    { href: "/", label: "Dashboard", icon: <LayoutDashboard size={20} /> },
    { href: "/monitoring", label: "Live Monitoring", icon: <Activity size={20} /> },
    { href: "/topology", label: "Network Topology", icon: <Network size={20} /> },
    { href: "/devices", label: "Devices", icon: <MonitorSmartphone size={20} /> },
    { href: "/predictions", label: "AI Predictions", icon: <Brain size={20} /> },
  ];

  const analysisNav: NavItem[] = [
    { href: "/alerts", label: "Alerts", icon: <Bell size={20} />, badge: alertCount },
    { href: "/response", label: "Active Defense", icon: <ShieldAlert size={20} /> },
    { href: "/history", label: "Attack History", icon: <History size={20} /> },
    { href: "/logs", label: "Live Logs", icon: <Terminal size={20} /> },
    { href: "/reports", label: "Reports", icon: <FileText size={20} /> },
  ];

  const systemNav: NavItem[] = [
    { href: "/settings", label: "Settings", icon: <Settings size={20} /> },
  ];

  const renderNavItem = (item: NavItem) => {
    const isActive = pathname === item.href;
    return (
      <Link
        key={item.href}
        href={item.href}
        className={`nav-item ${isActive ? "active" : ""}`}
      >
        <span className="nav-item-icon">{item.icon}</span>
        {item.label}
        {item.badge !== undefined && item.badge > 0 && (
          <span className="nav-badge">{item.badge}</span>
        )}
      </Link>
    );
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={22} color="white" />
        </div>
        <div>
          <h1>NIDS v2</h1>
          <span>Industrial NDR</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="sidebar-section-label">Overview</span>
        {mainNav.map(renderNavItem)}

        <span className="sidebar-section-label">Analysis</span>
        {analysisNav.map(renderNavItem)}

        <span className="sidebar-section-label">System</span>
        {systemNav.map(renderNavItem)}
      </nav>

      <div className="sidebar-footer">
        <div className={`connection-dot ${isConnected ? "" : "disconnected"}`} />
        {isConnected ? "NDR Live Connected" : "NDR Disconnected"}
      </div>
    </aside>
  );
}
