export type VisualKind = "ctf" | "ai" | "code" | "math" | "study" | "markdown" | "journal";
export type CoverVisual = VisualKind | "ctf-flow" | "ctf-binary";

const normalize = (value: string) => value.normalize("NFKC").trim().toLowerCase();

function classifySubject(value: string): VisualKind | undefined {
  const subject = normalize(value);
  if (!subject) return undefined;

  // Match subjects, not arbitrary substrings: "Go" must not match "blog".
  if (/(?:^|[\s/·_-])(?:ctf|writeups?|reverse|reversing|crypto|pwn)(?:$|[\s/·_-])/.test(subject) || /逆向|密码学|比赛题解/.test(subject)) return "ctf";
  if (/(?:^|[\s/·_-])(?:ai|agents?|bots?|codex|llm|machine learning)(?:$|[\s/·_-])/.test(subject) || /人工智能|机器学习/.test(subject)) return "ai";
  if (/(?:^|[\s/·_-])(?:math|mathematics|algebra|calculus)(?:$|[\s/·_-])/.test(subject) || /线性|数学|公式|代数|微积分/.test(subject)) return "math";
  if (/(?:^|[\s/·_-])(?:c\+\+|cpp|c#|csharp|python|javascript|typescript|java|golang|go|rust|algorithm|algorithms|programming)(?:$|[\s/·_-])/.test(subject) || /数据结构|算法|编程|程序设计/.test(subject)) return "code";
  if (/(?:^|[\s/·_-])(?:english|study|exam|revision)(?:$|[\s/·_-])/.test(subject) || /复习|英语|军事|期末|学习/.test(subject)) return "study";
  if (/(?:^|[\s/·_-])(?:markdown|md)(?:$|[\s/·_-])/.test(subject)) return "markdown";
  return undefined;
}

export function getPostVisual(data: { category?: string | null; tags?: string[] }): VisualKind {
  // The author's explicit category wins over incidental tags such as notes or CTF.
  const categoryKind = classifySubject(data.category || "");
  if (categoryKind) return categoryKind;

  const tagKinds = new Set((data.tags || []).map(classifySubject));
  for (const kind of ["ctf", "ai", "math", "code", "study", "markdown"] as const) {
    if (tagKinds.has(kind)) return kind;
  }
  const labels = [data.category || "", ...(data.tags || [])].map(normalize);
  if (labels.some((label) => /^(?:notes?|笔记|学习笔记)$/.test(label))) return "markdown";
  return "journal";
}

export function getPostCoverVisual(data: { category?: string | null; tags?: string[] }, slug: string): CoverVisual {
  const kind = getPostVisual(data);
  if (kind !== "ctf") return kind;

  // A stable slug hash keeps covers consistent across builds and article ordering.
  let hash = 2166136261;
  for (const character of normalize(slug)) {
    hash = Math.imul(hash ^ character.codePointAt(0)!, 16777619) >>> 0;
  }
  const variants = ["ctf", "ctf-flow", "ctf-binary"] as const;
  return variants[hash % variants.length];
}

export const visualLabels: Record<VisualKind, string> = {
  ctf: "CTF / WRITEUP",
  ai: "AI / AGENT",
  code: "CODE / NOTES",
  math: "MATH / NOTES",
  study: "STUDY / NOTES",
  markdown: "MARKDOWN / NOTES",
  journal: "JOURNAL / NOTES",
};
