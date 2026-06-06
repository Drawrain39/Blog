export type EnglishB2OptionKey = "A" | "B" | "C" | "D";

export interface EnglishB2Option {
	key: EnglishB2OptionKey;
	text: string;
}

export interface EnglishB2Question {
	id: string;
	unit: number;
	unitCode: string;
	number: number;
	question: string;
	options: EnglishB2Option[];
	stemTranslation: string;
	optionTranslation: string;
	answer: EnglishB2OptionKey;
	keyVocabulary: string;
}

interface DraftQuestion {
	unit: number;
	unitCode: string;
	number: number;
	question: string;
	options: EnglishB2Option[];
	stemTranslation: string;
	optionTranslation: string;
	answer: string;
	keyVocabulary: string;
}

function cleanInline(value: string) {
	return value.trim().replace(/\s+/g, " ");
}

function toOptionKey(value: string): EnglishB2OptionKey | null {
	const key = value.trim().toUpperCase().charAt(0);
	if (key === "A" || key === "B" || key === "C" || key === "D") return key;
	return null;
}

function createQuestion(draft: DraftQuestion): EnglishB2Question | null {
	const answer = toOptionKey(draft.answer);
	if (!answer || !draft.question || draft.options.length === 0) return null;

	return {
		id: `${draft.unitCode}-${draft.number}`,
		unit: draft.unit,
		unitCode: draft.unitCode,
		number: draft.number,
		question: cleanInline(draft.question),
		options: draft.options,
		stemTranslation: cleanInline(draft.stemTranslation),
		optionTranslation: cleanInline(draft.optionTranslation),
		answer,
		keyVocabulary: cleanInline(draft.keyVocabulary),
	};
}

export function parseEnglishB2Quiz(markdown: string): EnglishB2Question[] {
	const questions: EnglishB2Question[] = [];
	const lines = markdown.replace(/\r\n/g, "\n").split("\n");

	let inExercises = false;
	let currentUnit = 0;
	let currentUnitCode = "";
	let current: DraftQuestion | null = null;

	function flushCurrent() {
		if (!current) return;
		const parsed = createQuestion(current);
		if (parsed) questions.push(parsed);
		current = null;
	}

	for (const rawLine of lines) {
		const line = rawLine.trim();
		if (!line) continue;

		if (/^##\s+练习题/.test(line)) {
			inExercises = true;
			continue;
		}
		if (!inExercises) continue;

		const unitMatch = line.match(/^###\s+单元\s*(\d+)：\s*(B2U\d+)/);
		if (unitMatch) {
			flushCurrent();
			currentUnit = Number(unitMatch[1]);
			currentUnitCode = unitMatch[2];
			continue;
		}

		const numberMatch = line.match(/^\*\*第\s*(\d+)\s*题\*\*$/);
		if (numberMatch) {
			flushCurrent();
			current = {
				unit: currentUnit,
				unitCode: currentUnitCode,
				number: Number(numberMatch[1]),
				question: "",
				options: [],
				stemTranslation: "",
				optionTranslation: "",
				answer: "",
				keyVocabulary: "",
			};
			continue;
		}

		if (!current) continue;

		const optionMatch = line.match(/^-\s*([A-D])\.\s*(.*)$/);
		if (optionMatch) {
			current.options.push({
				key: optionMatch[1] as EnglishB2OptionKey,
				text: cleanInline(optionMatch[2]),
			});
			continue;
		}

		const fieldMatch = line.match(/^\*\*(.+?)：\*\*\s*(.*)$/);
		if (!fieldMatch) continue;

		const [, label, value] = fieldMatch;
		if (label === "原题") current.question = value;
		if (label === "题干翻译") current.stemTranslation = value;
		if (label === "选项翻译") current.optionTranslation = value;
		if (label === "答案") current.answer = value;
		if (label === "重点词汇") current.keyVocabulary = value;
	}

	flushCurrent();
	return questions;
}
