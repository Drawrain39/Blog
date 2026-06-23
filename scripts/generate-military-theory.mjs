import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDir, "..");
const sourceRoot = resolve(projectRoot, "..");

const sources = [
	"第1章 中国国防  题库（2025年）.md",
	"第2章 国家安全 题库（2025年）.md",
	"第3章 军事思想 题库（2025年）.md",
	"第4章 现代战争 题库（2025年）.md",
	"第5章 信息化装备 题库（2025年）.md",
];

const sectionTypeByName = [
	["填空", "fill"],
	["单项", "single"],
	["多项", "multiple"],
	["判断", "judge"],
	["简答", "short"],
	["论述", "essay"],
];

function cleanInline(value) {
	return value
		.replace(/\\\./g, ".")
		.replace(/<sup>(.*?)<\/sup>/gi, "^$1")
		.replace(/\u3000/g, " ")
		.replace(/[ \t]+/g, " ")
		.trim();
}

function cleanAnswer(value) {
	return cleanInline(value).replace(/。$/u, "");
}

function stripBoldNumber(line) {
	return line
		.replace(/^\*\*(\d+[、.])\*\*\s*/u, "$1")
		.replace(/^\*\*(\d+)、\*\*\s*/u, "$1、")
		.replace(/^(\d+)\\\./u, "$1.");
}

function parseSectionType(line) {
	const match = line.match(/^\*\*(.+?)\*\*$/u);
	if (!match) return null;
	for (const [keyword, type] of sectionTypeByName) {
		if (match[1].includes(keyword)) return type;
	}
	return null;
}

function parseNumberedLine(rawLine) {
	const line = stripBoldNumber(rawLine.trim());
	const match = line.match(/^(\d+)[、.](.*)$/u);
	if (!match) return null;
	return {
		number: Number(match[1]),
		body: match[2],
	};
}

function extractAnswers(body) {
	const answers = [...body.matchAll(/【([^】]+)】/gu)].map((match) =>
		cleanAnswer(match[1]),
	);
	const text = body.replace(/【[^】]+】/gu, "").trimEnd();
	return { text, answers };
}

function replaceBlankRuns(text, answers, blankFactory) {
	let result = text;
	for (let index = 0; index < answers.length; index += 1) {
		const replacement = blankFactory(answers[index], index);
		if (/\s+/u.test(result)) {
			result = result.replace(/\s+/u, replacement);
		} else {
			result += replacement;
		}
	}
	return cleanInline(result);
}

function formatFill(text, answers) {
	return replaceBlankRuns(text, answers, (answer) => `（${answer}）`);
}

function blankFill(text, answers) {
	return replaceBlankRuns(text, answers, () => "____");
}

function splitAnswerKeys(value) {
	return cleanInline(value)
		.toUpperCase()
		.replace(/[^A-F]/gu, "")
		.split("");
}

function parseChapter(filename, chapter) {
	const markdown = readFileSync(resolve(sourceRoot, filename), "utf8").replace(/\r\n/g, "\n");
	const lines = markdown.split("\n");
	const chapterTitle = cleanInline(lines.find((line) => line.trim()) ?? `第${chapter}章`);
	const questions = [];

	let section = null;
	let current = null;

	function flushCurrent() {
		if (!current) return;
		if ((current.type === "single" || current.type === "multiple") && current.options.length) {
			questions.push(current);
		}
		if ((current.type === "short" || current.type === "essay") && current.answerLines.length) {
			questions.push(current);
		}
		current = null;
	}

	for (const rawLine of lines) {
		const trimmed = rawLine.trim();
		if (!trimmed) continue;

		const nextSection = parseSectionType(trimmed);
		if (nextSection) {
			flushCurrent();
			section = nextSection;
			continue;
		}

		if (!section) continue;

		const numbered = parseNumberedLine(trimmed);
		if (numbered) {
			if (section === "fill") {
				const { text, answers } = extractAnswers(numbered.body);
				if (!answers.length) continue;
				const id = `c${chapter}-fill-${numbered.number}`;
				questions.push({
					id,
					chapter,
					chapterTitle,
					type: "fill",
					number: numbered.number,
					prompt: blankFill(text, answers),
					filledPrompt: formatFill(text, answers),
					answers,
					answerText: answers.join("；"),
				});
				continue;
			}

			if (section === "single" || section === "multiple") {
				flushCurrent();
				const { text, answers } = extractAnswers(numbered.body);
				const answerKeys = splitAnswerKeys(answers.at(-1) ?? "");
				current = {
					id: `c${chapter}-${section}-${numbered.number}`,
					chapter,
					chapterTitle,
					type: section,
					number: numbered.number,
					prompt: cleanInline(text),
					options: [],
					answerKeys,
					answerText: answerKeys.join(""),
				};
				continue;
			}

			if (section === "judge") {
				const { text, answers } = extractAnswers(numbered.body);
				if (!answers.length) continue;
				questions.push({
					id: `c${chapter}-judge-${numbered.number}`,
					chapter,
					chapterTitle,
					type: "judge",
					number: numbered.number,
					prompt: cleanInline(text),
					answers: [answers[0]],
					answerText: answers[0],
				});
				continue;
			}

			if (section === "short" || section === "essay") {
				flushCurrent();
				current = {
					id: `c${chapter}-${section}-${numbered.number}`,
					chapter,
					chapterTitle,
					type: section,
					number: numbered.number,
					prompt: cleanInline(numbered.body),
					answerLines: [],
					answerText: "",
				};
				continue;
			}
		}

		if ((section === "single" || section === "multiple") && current) {
			const optionMatch = trimmed.match(/^([A-F])\.\s*(.+)$/u);
			if (optionMatch) {
				current.options.push({
					key: optionMatch[1],
					text: cleanInline(optionMatch[2]),
				});
			}
			continue;
		}

		if ((section === "short" || section === "essay") && current) {
			if (/^【答案要点】$/u.test(trimmed)) continue;
			current.answerLines.push(cleanInline(trimmed));
			current.answerText = current.answerLines.join("\n");
		}
	}

	flushCurrent();
	return { chapter, title: chapterTitle, filename, questions };
}

function typeTitle(type) {
	return {
		fill: "填空题",
		single: "单项选择题",
		multiple: "多项选择题",
		judge: "判断题",
		short: "简答题",
		essay: "论述题",
	}[type];
}

function renderArticleQuestion(question) {
	if (question.type === "fill") {
		return `${question.number}. ${question.filledPrompt}`;
	}

	if (question.type === "single" || question.type === "multiple") {
		const optionLines = question.options.map((option) => `   - ${option.key}. ${option.text}`);
		return [
			`${question.number}. ${question.prompt}`,
			"",
			...optionLines,
			"",
			`   **答案：** ${question.answerText}`,
		].join("\n");
	}

	if (question.type === "judge") {
		return `${question.number}. ${question.prompt}（${question.answerText}）`;
	}

	return [
		`${question.number}. ${question.prompt}`,
		"",
		"   **答案要点：**",
		...question.answerLines.map((line) => `   - ${line}`),
	].join("\n");
}

function buildKnowledge(chapters) {
	const knowledge = [];
	for (const chapter of chapters) {
		for (const question of chapter.questions) {
			if (question.type === "fill") {
				knowledge.push({
					id: `${question.id}-knowledge`,
					chapter: question.chapter,
					chapterTitle: question.chapterTitle,
					kind: "填空",
					title: `第 ${question.number} 条核心知识`,
					body: question.filledPrompt,
					points: [],
				});
			}
			if (question.type === "short" || question.type === "essay") {
				knowledge.push({
					id: `${question.id}-knowledge`,
					chapter: question.chapter,
					chapterTitle: question.chapterTitle,
					kind: question.type === "short" ? "简答" : "论述",
					title: question.prompt,
					body: "",
					points: question.answerLines,
				});
			}
		}
	}
	return knowledge;
}

function buildArticle(chapters) {
	const counts = chapters.flatMap((chapter) => chapter.questions);
	const total = counts.length;
	const statLine = [
		`选择题 ${counts.filter((q) => q.type === "single" || q.type === "multiple").length} 道`,
		`填空题 ${counts.filter((q) => q.type === "fill").length} 道`,
		`判断题 ${counts.filter((q) => q.type === "judge").length} 道`,
		`简答题 ${counts.filter((q) => q.type === "short").length} 道`,
		`论述题 ${counts.filter((q) => q.type === "essay").length} 道`,
	].join("，");

	const output = [
		"---",
		"title: 军事理论期末复习题库",
		"published: 2026-06-22",
		"description: 整理军事理论第一至五章知识点与题库，覆盖选择、填空、判断、简答和论述题。",
		"tags: [军事理论, 期末复习]",
		"category: 学习",
		"draft: false",
		"---",
		"",
		"> 本文由五份军事理论题库整理而来，覆盖中国国防、国家安全、军事思想、现代战争、信息化装备五章内容。",
		">",
		`> 共整理 ${total} 道题：${statLine}。填空题已统一改成括号答案格式，例如“国防的主体是（国家）”。`,
		">",
		"> 整理日期：2026-06-22",
		"",
		"[进入刷题模式](/military-theory-quiz/)",
		"",
		"## 目录",
		"",
		...chapters.map((chapter) => `- [${chapter.title}](#${chapter.title.replace(/\s+/gu, "-").toLowerCase()})`),
		"",
	];

	for (const chapter of chapters) {
		output.push(`## ${chapter.title}`, "");
		for (const type of ["fill", "single", "multiple", "judge", "short", "essay"]) {
			const typedQuestions = chapter.questions.filter((question) => question.type === type);
			if (!typedQuestions.length) continue;
			output.push(`### ${typeTitle(type)}`, "");
			output.push(...typedQuestions.map(renderArticleQuestion).flatMap((item) => [item, ""]));
		}
	}

	return `${output.join("\n").trim()}\n`;
}

const chapters = sources.map((source, index) => parseChapter(source, index + 1));
const questions = chapters.flatMap((chapter) => chapter.questions);
const knowledge = buildKnowledge(chapters);

mkdirSync(resolve(projectRoot, "src/data"), { recursive: true });

writeFileSync(
	resolve(projectRoot, "src/content/posts/military-theory.md"),
	buildArticle(chapters),
	"utf8",
);

writeFileSync(
	resolve(projectRoot, "src/data/military-theory-quiz.json"),
	`${JSON.stringify({ chapters, questions, knowledge }, null, 2)}\n`,
	"utf8",
);

console.log(`Generated ${questions.length} questions and ${knowledge.length} knowledge cards.`);
