// Minimal typings for react-plotly.js (no @types package is installed, and
// package.json is intentionally left untouched). Only the props that
// DriftMonitor uses are described.

declare module "react-plotly.js" {
  import type { ComponentType, CSSProperties } from "react";

  /** A single plotly trace (scatter etc.). Plotly's trace schema is large; keys stay open. */
  export type PlotTrace = Record<string, unknown>;

  /** Plotly layout object. */
  export type PlotLayout = Record<string, unknown>;

  /** Plotly config object. */
  export type PlotConfig = Record<string, unknown>;

  /** One clicked point inside a plotly click event. */
  export interface PlotPoint {
    customdata?: unknown;
    [key: string]: unknown;
  }

  /** Payload passed to onClick. */
  export interface PlotMouseEvent {
    points?: PlotPoint[];
  }

  export interface PlotProps {
    data: PlotTrace[];
    layout?: PlotLayout;
    config?: PlotConfig;
    style?: CSSProperties;
    className?: string;
    useResizeHandler?: boolean;
    onClick?: (event: PlotMouseEvent) => void;
  }

  const Plot: ComponentType<PlotProps>;
  export default Plot;
}
