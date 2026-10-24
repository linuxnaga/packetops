import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart, PieChart, ScatterChart } from "echarts/charts";
import { DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";
import { isDark } from "../lib/theme";

echarts.use([BarChart, LineChart, PieChart, ScatterChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent, MarkLineComponent, CanvasRenderer]);

export function EChart({ option, height = 260, label, onClick }: { option: EChartsCoreOption; height?: number; label: string; onClick?: (p: any) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  useEffect(() => {
    if (!ref.current) return;
    chart.current = echarts.init(ref.current, isDark() ? "dark" : undefined, { renderer: "canvas" });
    const ro = new ResizeObserver(() => chart.current?.resize());
    ro.observe(ref.current);
    return () => { ro.disconnect(); chart.current?.dispose(); chart.current = null; };
  }, []);
  useEffect(() => {
    chart.current?.setOption({ backgroundColor: "transparent", ...option }, true);
  }, [option]);
  useEffect(() => {
    if (!chart.current || !onClick) return;
    chart.current.on("click", onClick);
    return () => { chart.current?.off("click", onClick); };
  }, [onClick]);
  return <div ref={ref} role="img" aria-label={label} style={{ height, width: "100%" }} />;
}
