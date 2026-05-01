// Tiny HCL code editor: react-simple-code-editor (textarea + ghost
// pre layer) + prismjs's hcl grammar for syntax colors. Re-used by
// both the global gateway.hcl editor and the per-device fragment
// editor.

import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-hcl";
import "prismjs/themes/prism.css";

export function HCLEditor({
  value,
  onChange,
  minHeight = 320,
}: {
  value: string;
  onChange: (v: string) => void;
  minHeight?: number;
}) {
  return (
    <Editor
      value={value}
      onValueChange={onChange}
      highlight={(code) => Prism.highlight(code, Prism.languages.hcl, "hcl")}
      padding={16}
      style={{
        fontFamily: "ui-monospace, SFMono-Regular, monospace",
        fontSize: 12,
        background: "#fafafa",
        minHeight,
      }}
      className="flex-1"
    />
  );
}
