import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { linkify } from "../pages/Console";

function renderText(text: string, onCapture = vi.fn()) {
  return render(<MemoryRouter><div>{linkify(text, onCapture)}</div></MemoryRouter>);
}

describe("console linkify", () => {
  it("links frames, flows and findings to their screens", () => {
    renderText("RST in #33 on t5, see F2");
    expect(screen.getByRole("link", { name: "#33" })).toHaveAttribute("href", `/workbench?filter=${encodeURIComponent("frame.number == 33")}`);
    expect(screen.getByRole("link", { name: "t5" })).toHaveAttribute("href", "/flows?flow=t5");
    expect(screen.getByRole("link", { name: "F2" })).toHaveAttribute("href", "/findings?f=F2");
  });
  it("leaves ordinary words and addresses alone", () => {
    renderText("10.2.2.21:8080 timed out after 3 SYNs");
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
  it("makes capture ids selectable", () => {
    const onCapture = vi.fn();
    renderText("use cap_c88faa610aead60b7238", onCapture);
    screen.getByRole("button", { name: "cap_c88faa610aead60b7238" }).click();
    expect(onCapture).toHaveBeenCalledWith("cap_c88faa610aead60b7238");
  });
});
