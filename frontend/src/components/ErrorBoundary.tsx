// ErrorBoundary.tsx — Catches rendering errors so the whole app doesn't go blank.
//
// React functional components can't catch errors in their children.
// Error boundaries MUST be class components — this is one of the few cases
// where React still requires a class. When a child component throws during
// render, this catches it and shows an error message instead of a blank page.

import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  name?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error(`[ErrorBoundary${this.props.name ? ` - ${this.props.name}` : ""}]`, error, info);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div style={{
          padding: 20,
          color: "#ef4444",
          background: "rgba(239,68,68,0.1)",
          borderRadius: 8,
          margin: 8,
          fontSize: 13,
          fontFamily: "monospace",
        }}>
          <strong>{this.props.name || "Component"} error:</strong>
          <br />
          {this.state.error?.message}
        </div>
      );
    }
    return this.props.children;
  }
}
