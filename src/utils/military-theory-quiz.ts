export type MilitaryTheoryQuestionType =
	| "fill"
	| "single"
	| "multiple"
	| "judge"
	| "short"
	| "essay";

export interface MilitaryTheoryChapter {
	chapter: number;
	title: string;
	filename: string;
}

export interface MilitaryTheoryOption {
	key: string;
	text: string;
}

export interface MilitaryTheoryQuestion {
	id: string;
	chapter: number;
	chapterTitle: string;
	type: MilitaryTheoryQuestionType;
	number: number;
	prompt: string;
	filledPrompt?: string;
	options?: MilitaryTheoryOption[];
	answerKeys?: string[];
	answers?: string[];
	answerLines?: string[];
	answerText: string;
}

export interface MilitaryTheoryKnowledge {
	id: string;
	chapter: number;
	chapterTitle: string;
	kind: string;
	title: string;
	body: string;
	points: string[];
}

export interface MilitaryTheoryData {
	chapters: MilitaryTheoryChapter[];
	questions: MilitaryTheoryQuestion[];
	knowledge: MilitaryTheoryKnowledge[];
}

export const militaryTheoryTypeLabels: Record<MilitaryTheoryQuestionType, string> = {
	fill: "填空",
	single: "单选",
	multiple: "多选",
	judge: "判断",
	short: "简答",
	essay: "论述",
};

export function isObjectiveMilitaryQuestion(question: MilitaryTheoryQuestion) {
	return (
		question.type === "fill" ||
		question.type === "single" ||
		question.type === "multiple" ||
		question.type === "judge"
	);
}
