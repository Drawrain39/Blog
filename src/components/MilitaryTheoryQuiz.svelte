<script lang="ts">
import Icon from "@iconify/svelte";
import { onMount } from "svelte";
import type {
	MilitaryTheoryData,
	MilitaryTheoryKnowledge,
	MilitaryTheoryQuestion,
	MilitaryTheoryQuestionType,
} from "../utils/military-theory-quiz";
import {
	isObjectiveMilitaryQuestion,
	militaryTheoryTypeLabels,
} from "../utils/military-theory-quiz";

export let data: MilitaryTheoryData = {
	chapters: [],
	questions: [],
	knowledge: [],
};

type View = "practice" | "knowledge";
type Mode = "all" | "wrong" | "starred";
type Order = "sequential" | "random";
type SelfMark = "known" | "review";

interface StoredAnswer {
	values: string[];
	text: string;
	correct: boolean;
	self?: SelfMark;
}

interface DraftAnswer {
	values: string[];
	fillInput: string;
	writtenAnswer: string;
	showAnswer: boolean;
}

interface PersistedState {
	answered: Record<string, StoredAnswer>;
	wrongIds: string[];
	starredIds: string[];
	view: View;
	chapterFilter: string;
	typeFilter: MilitaryTheoryQuestionType | "all";
	mode: Mode;
	order: Order;
	currentIndex: number;
	showQuestionList: boolean;
	search: string;
	orderSeed: number;
	sessionCorrect: number;
	sessionTotal: number;
	drafts: Record<string, DraftAnswer>;
}

const storageKey = "drawrain-military-theory-quiz-v1";
const validModes = new Set<Mode>(["all", "wrong", "starred"]);
const validOrders = new Set<Order>(["sequential", "random"]);
const validViews = new Set<View>(["practice", "knowledge"]);
const typeFilters: Array<{ value: MilitaryTheoryQuestionType | "all"; label: string }> = [
	{ value: "all", label: "全部题型" },
	{ value: "single", label: "单选" },
	{ value: "multiple", label: "多选" },
	{ value: "fill", label: "填空" },
	{ value: "judge", label: "判断" },
	{ value: "short", label: "简答" },
	{ value: "essay", label: "论述" },
];

let view: View = "practice";
let chapterFilter = "all";
let typeFilter: MilitaryTheoryQuestionType | "all" = "all";
let mode: Mode = "all";
let order: Order = "sequential";
let currentIndex = 0;
let selectedKeys: string[] = [];
let fillInput = "";
let writtenAnswer = "";
let showAnswer = false;
let showQuestionList = false;
let search = "";
let answered: Record<string, StoredAnswer> = {};
let drafts: Record<string, DraftAnswer> = {};
let wrongIds: string[] = [];
let starredIds: string[] = [];
let sessionCorrect = 0;
let sessionTotal = 0;
let orderSeed = 0;
let mounted = false;
let activeQuestionId = "";
let saveNotice = "";
let saveNoticeTimer: ReturnType<typeof setTimeout> | undefined;
let lastSavedState = "";
let persistedState: PersistedState;

$: chapters = data.chapters ?? [];
$: questions = data.questions ?? [];
$: knowledge = data.knowledge ?? [];
$: questionIds = new Set(questions.map((question) => question.id));
$: wrongSet = new Set(wrongIds);
$: starredSet = new Set(starredIds);
$: chapterFilters = [
	{ value: "all", label: "全部章节" },
	...chapters.map((chapter) => ({
		value: String(chapter.chapter),
		label: chapter.title.replace(/^第(.+?)章\s*/u, "第$1章 "),
	})),
];
$: visibleQuestions = buildVisibleQuestions(
	questions,
	chapterFilter,
	typeFilter,
	mode,
	wrongSet,
	starredSet,
	order,
	orderSeed,
);
$: if (currentIndex >= visibleQuestions.length) {
	currentIndex = Math.max(0, visibleQuestions.length - 1);
}
$: currentQuestion = visibleQuestions[currentIndex] ?? null;
$: savedRecord = currentQuestion ? answered[currentQuestion.id] : undefined;
$: resolvedSubmitted = Boolean(savedRecord);
$: canSubmitCurrent =
	Boolean(currentQuestion) &&
	!resolvedSubmitted &&
	(currentQuestion?.type === "fill"
		? Boolean(fillInput.trim())
		: currentQuestion?.type === "short" || currentQuestion?.type === "essay"
			? true
			: selectedKeys.length > 0);
$: progressPercent =
	visibleQuestions.length > 0
		? Math.round(((currentIndex + 1) / visibleQuestions.length) * 100)
		: 0;
$: answeredInScope = visibleQuestions.filter((question) => answered[question.id]).length;
$: accuracy =
	sessionTotal > 0 ? Math.round((sessionCorrect / sessionTotal) * 100) : 0;
$: filteredKnowledge = buildKnowledgeCards(knowledge, chapterFilter, search);
$: objectiveCount = questions.filter(isObjectiveMilitaryQuestion).length;
$: subjectiveCount = questions.length - objectiveCount;

$: if (currentQuestion && currentQuestion.id !== activeQuestionId) {
	activeQuestionId = currentQuestion.id;
	const saved = answered[currentQuestion.id];
	const draft = drafts[currentQuestion.id];
	selectedKeys = saved?.values ? [...saved.values] : draft?.values ? [...draft.values] : [];
	fillInput = currentQuestion.type === "fill" ? saved?.text ?? draft?.fillInput ?? "" : "";
	writtenAnswer =
		currentQuestion.type === "short" || currentQuestion.type === "essay"
			? saved?.text ?? draft?.writtenAnswer ?? ""
			: "";
	showAnswer = Boolean(saved) || Boolean(draft?.showAnswer);
}

$: if (mounted && currentQuestion && !resolvedSubmitted) {
	selectedKeys;
	fillInput;
	writtenAnswer;
	showAnswer;
	syncCurrentDraft();
}

$: persistedState = {
	answered,
	wrongIds,
	starredIds,
	view,
	chapterFilter,
	typeFilter,
	mode,
	order,
	currentIndex,
	showQuestionList,
	search,
	orderSeed,
	sessionCorrect,
	sessionTotal,
	drafts,
};

$: if (mounted) {
	saveState(persistedState);
}

onMount(() => {
	const saved = loadSavedState();
	if (saved) {
		try {
			const parsed = JSON.parse(saved);
			answered = sanitizeAnswered(parsed.answered);
			drafts = sanitizeDrafts(parsed.drafts);
			wrongIds = sanitizeIds(parsed.wrongIds);
			starredIds = sanitizeIds(parsed.starredIds);
			view = validViews.has(parsed.view) ? parsed.view : "practice";
			chapterFilter = isValidChapter(parsed.chapterFilter) ? parsed.chapterFilter : "all";
			typeFilter = isValidType(parsed.typeFilter) ? parsed.typeFilter : "all";
			mode = validModes.has(parsed.mode) ? parsed.mode : "all";
			order = validOrders.has(parsed.order) ? parsed.order : "sequential";
			currentIndex = Number.isFinite(parsed.currentIndex)
				? Math.max(0, parsed.currentIndex)
				: 0;
			showQuestionList = parsed.showQuestionList ?? false;
			search = typeof parsed.search === "string" ? parsed.search : "";
			orderSeed = Number.isFinite(parsed.orderSeed) ? parsed.orderSeed : 0;
			sessionCorrect = Number.isFinite(parsed.sessionCorrect)
				? Math.max(0, parsed.sessionCorrect)
				: 0;
			sessionTotal = Number.isFinite(parsed.sessionTotal)
				? Math.max(0, parsed.sessionTotal)
				: 0;
			lastSavedState = saved;
		} catch {
			resetAll(false);
		}
	}
	activeQuestionId = "";
	mounted = true;
});

function loadSavedState() {
	try {
		return localStorage.getItem(storageKey);
	} catch {
		return null;
	}
}

function saveState(state: PersistedState) {
	try {
		const serialized = JSON.stringify(state);
		if (serialized === lastSavedState) return true;
		localStorage.setItem(storageKey, serialized);
		lastSavedState = serialized;
		return true;
	} catch {
		// localStorage may be blocked; the page still works without persistence.
		return false;
	}
}

function sanitizeIds(value: unknown) {
	if (!Array.isArray(value)) return [];
	return value.filter((id): id is string => typeof id === "string" && questionIds.has(id));
}

function sanitizeAnswered(value: unknown) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return {};
	const entries = Object.entries(value).filter(([id, record]) => {
		if (!questionIds.has(id)) return false;
		if (!record || typeof record !== "object" || Array.isArray(record)) return false;
		const answer = record as Partial<StoredAnswer>;
		return (
			Array.isArray(answer.values) &&
			answer.values.every((item) => typeof item === "string") &&
			typeof answer.text === "string" &&
			typeof answer.correct === "boolean"
		);
	});
	return Object.fromEntries(entries) as Record<string, StoredAnswer>;
}

function sanitizeDrafts(value: unknown) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return {};
	const entries = Object.entries(value).flatMap(([id, record]) => {
		if (!questionIds.has(id)) return [];
		if (!record || typeof record !== "object" || Array.isArray(record)) return [];
		const draft = record as Partial<DraftAnswer>;
		const sanitized: DraftAnswer = {
			values: Array.isArray(draft.values)
				? draft.values.filter((item): item is string => typeof item === "string")
				: [],
			fillInput: typeof draft.fillInput === "string" ? draft.fillInput : "",
			writtenAnswer: typeof draft.writtenAnswer === "string" ? draft.writtenAnswer : "",
			showAnswer: draft.showAnswer === true,
		};
		return hasDraftContent(sanitized) ? [[id, sanitized] as const] : [];
	});
	return Object.fromEntries(entries) as Record<string, DraftAnswer>;
}

function hasDraftContent(draft: DraftAnswer) {
	return (
		draft.values.length > 0 ||
		Boolean(draft.fillInput.trim()) ||
		Boolean(draft.writtenAnswer.trim()) ||
		draft.showAnswer
	);
}

function sameDraft(left: DraftAnswer | undefined, right: DraftAnswer) {
	return (
		Boolean(left) &&
		sameSet(left?.values ?? [], right.values) &&
		(left?.fillInput ?? "") === right.fillInput &&
		(left?.writtenAnswer ?? "") === right.writtenAnswer &&
		Boolean(left?.showAnswer) === right.showAnswer
	);
}

function syncCurrentDraft() {
	if (!currentQuestion || resolvedSubmitted) return;
	const isFill = currentQuestion.type === "fill";
	const isWritten = currentQuestion.type === "short" || currentQuestion.type === "essay";
	const isChoice =
		currentQuestion.type === "single" ||
		currentQuestion.type === "multiple" ||
		currentQuestion.type === "judge";
	const draft: DraftAnswer = {
		values: isChoice ? [...selectedKeys] : [],
		fillInput: isFill ? fillInput : "",
		writtenAnswer: isWritten ? writtenAnswer : "",
		showAnswer,
	};

	if (!hasDraftContent(draft)) {
		removeDraft(currentQuestion.id);
		return;
	}
	if (sameDraft(drafts[currentQuestion.id], draft)) return;
	drafts = {
		...drafts,
		[currentQuestion.id]: draft,
	};
}

function removeDraft(id: string) {
	if (!drafts[id]) return;
	const { [id]: _removed, ...rest } = drafts;
	drafts = rest;
}

function isValidChapter(value: unknown) {
	if (value === "all") return true;
	return typeof value === "string" && chapters.some((chapter) => String(chapter.chapter) === value);
}

function isValidType(value: unknown): value is MilitaryTheoryQuestionType | "all" {
	return value === "all" || typeFilters.some((type) => type.value === value);
}

function buildVisibleQuestions(
	source: MilitaryTheoryQuestion[],
	chapter: string,
	type: MilitaryTheoryQuestionType | "all",
	selectedMode: Mode,
	wrong: Set<string>,
	starred: Set<string>,
	selectedOrder: Order,
	seed: number,
) {
	let list = source;
	if (chapter !== "all") {
		list = list.filter((question) => String(question.chapter) === chapter);
	}
	if (type !== "all") {
		list = list.filter((question) => question.type === type);
	}
	if (selectedMode === "wrong") {
		list = list.filter((question) => wrong.has(question.id));
	}
	if (selectedMode === "starred") {
		list = list.filter((question) => starred.has(question.id));
	}
	if (selectedOrder === "random") {
		return shuffleQuestions(list, seed || 7207);
	}
	return list;
}

function buildKnowledgeCards(
	source: MilitaryTheoryKnowledge[],
	chapter: string,
	keyword: string,
) {
	let list = source;
	if (chapter !== "all") {
		list = list.filter((item) => String(item.chapter) === chapter);
	}
	const needle = keyword.trim().toLowerCase();
	if (needle) {
		list = list.filter((item) =>
			[item.chapterTitle, item.kind, item.title, item.body, ...item.points]
				.join(" ")
				.toLowerCase()
				.includes(needle),
		);
	}
	return list;
}

function shuffleQuestions(source: MilitaryTheoryQuestion[], seed: number) {
	const list = [...source];
	let state = seed || 7207;
	for (let index = list.length - 1; index > 0; index -= 1) {
		state = (state * 9301 + 49297) % 233280;
		const target = Math.floor((state / 233280) * (index + 1));
		[list[index], list[target]] = [list[target], list[index]];
	}
	return list;
}

function nextRandomSeed() {
	return (Date.now() + Math.floor(Math.random() * 233280)) % 233280 || 7207;
}

function changeView(value: View) {
	view = value;
}

function changeChapter(value: string) {
	chapterFilter = value;
	goToQuestion(0);
}

function changeType(value: MilitaryTheoryQuestionType | "all") {
	typeFilter = value;
	goToQuestion(0);
}

function changeMode(value: Mode) {
	mode = value;
	goToQuestion(0);
}

function changeOrder(value: Order) {
	order = value;
	if (order === "random") orderSeed = nextRandomSeed();
	goToQuestion(0);
}

function reshuffle() {
	order = "random";
	orderSeed = nextRandomSeed();
	goToQuestion(0);
}

function goToQuestion(index: number) {
	currentIndex = Math.min(Math.max(index, 0), Math.max(visibleQuestions.length - 1, 0));
	activeQuestionId = "";
}

function nextQuestion() {
	if (currentIndex < visibleQuestions.length - 1) goToQuestion(currentIndex + 1);
}

function previousQuestion() {
	if (currentIndex > 0) goToQuestion(currentIndex - 1);
}

function toggleStar() {
	if (!currentQuestion) return;
	if (starredIds.includes(currentQuestion.id)) {
		starredIds = starredIds.filter((id) => id !== currentQuestion.id);
	} else {
		starredIds = [...starredIds, currentQuestion.id];
	}
}

function toggleKey(key: string) {
	if (!currentQuestion || resolvedSubmitted) return;
	if (currentQuestion.type === "multiple") {
		selectedKeys = selectedKeys.includes(key)
			? selectedKeys.filter((item) => item !== key)
			: [...selectedKeys, key].sort();
		return;
	}
	selectedKeys = selectedKeys[0] === key ? [] : [key];
}

function canSubmit(question: MilitaryTheoryQuestion) {
	if (resolvedSubmitted) return false;
	if (question.type === "fill") return Boolean(fillInput.trim());
	if (question.type === "short" || question.type === "essay") return true;
	return selectedKeys.length > 0;
}

function submitAnswer() {
	if (!currentQuestion || !canSubmit(currentQuestion)) return;

	if (currentQuestion.type === "short" || currentQuestion.type === "essay") {
		showAnswer = true;
		return;
	}

	const correct = evaluateObjective(currentQuestion);
	const text = currentQuestion.type === "fill" ? fillInput.trim() : selectedKeys.join("");
	answered = {
		...answered,
		[currentQuestion.id]: {
			values: [...selectedKeys],
			text,
			correct,
		},
	};
	sessionTotal += 1;
	if (correct) {
		sessionCorrect += 1;
		wrongIds = wrongIds.filter((id) => id !== currentQuestion.id);
	} else if (!wrongIds.includes(currentQuestion.id)) {
		wrongIds = [...wrongIds, currentQuestion.id];
	}
	removeDraft(currentQuestion.id);
	showAnswer = true;
}

function markSubjective(self: SelfMark) {
	if (!currentQuestion) return;
	const correct = self === "known";
	const hadRecord = Boolean(answered[currentQuestion.id]);
	answered = {
		...answered,
		[currentQuestion.id]: {
			values: [],
			text: writtenAnswer.trim(),
			correct,
			self,
		},
	};
	if (!hadRecord) {
		sessionTotal += 1;
		if (correct) sessionCorrect += 1;
	}
	if (correct) {
		wrongIds = wrongIds.filter((id) => id !== currentQuestion.id);
	} else if (!wrongIds.includes(currentQuestion.id)) {
		wrongIds = [...wrongIds, currentQuestion.id];
	}
	removeDraft(currentQuestion.id);
	showAnswer = true;
}

function evaluateObjective(question: MilitaryTheoryQuestion) {
	if (question.type === "single") {
		return selectedKeys[0] === question.answerKeys?.[0];
	}
	if (question.type === "multiple") {
		return sameSet(selectedKeys, question.answerKeys ?? []);
	}
	if (question.type === "judge") {
		return selectedKeys[0] === question.answerText;
	}
	if (question.type === "fill") {
		return evaluateFill(question, fillInput);
	}
	return false;
}

function sameSet(left: string[], right: string[]) {
	const normalizedLeft = [...left].sort().join("");
	const normalizedRight = [...right].sort().join("");
	return normalizedLeft === normalizedRight;
}

function normalizeAnswer(value: string) {
	return value
		.toLowerCase()
		.replace(/[（）()【】\s,，、;；.。/\\|_\-^]/gu, "");
}

function splitFillInput(value: string) {
	return value
		.split(/[、,，;；/\\|\n]+/u)
		.map((item) => item.trim())
		.filter(Boolean);
}

function evaluateFill(question: MilitaryTheoryQuestion, value: string) {
	const expected = question.answers ?? [];
	if (!expected.length) return false;
	const parts = splitFillInput(value);
	if (
		parts.length === expected.length &&
		parts.every((part, index) => normalizeAnswer(part) === normalizeAnswer(expected[index]))
	) {
		return true;
	}
	const normalizedWhole = normalizeAnswer(value);
	const normalizedExpected = expected.map(normalizeAnswer);
	return normalizedExpected.every((answer) => normalizedWhole.includes(answer));
}

function retryQuestion() {
	if (!currentQuestion) return;
	const { [currentQuestion.id]: _removed, ...rest } = answered;
	answered = rest;
	wrongIds = wrongIds.filter((id) => id !== currentQuestion.id);
	selectedKeys = [];
	fillInput = "";
	writtenAnswer = "";
	removeDraft(currentQuestion.id);
	showAnswer = false;
}

function resetSession() {
	sessionCorrect = 0;
	sessionTotal = 0;
	selectedKeys = [];
	fillInput = "";
	writtenAnswer = "";
	if (currentQuestion) removeDraft(currentQuestion.id);
	showAnswer = false;
}

function resetAll(confirmFirst = true) {
	if (confirmFirst && !confirm("清空军事理论刷题记录、错题和收藏？")) return;
	answered = {};
	drafts = {};
	wrongIds = [];
	starredIds = [];
	currentIndex = 0;
	selectedKeys = [];
	fillInput = "";
	writtenAnswer = "";
	showAnswer = false;
	sessionCorrect = 0;
	sessionTotal = 0;
	activeQuestionId = "";
}

function manualSave() {
	const saved = saveState(persistedState);
	flashSaveNotice(saved ? "已保存到本机" : "浏览器未允许保存");
}

function flashSaveNotice(message: string) {
	saveNotice = message;
	if (saveNoticeTimer) clearTimeout(saveNoticeTimer);
	saveNoticeTimer = setTimeout(() => {
		saveNotice = "";
	}, 1600);
}

function startChapterPractice(chapter: number) {
	view = "practice";
	chapterFilter = String(chapter);
	mode = "all";
	goToQuestion(0);
}

function typeLabel(type: MilitaryTheoryQuestionType) {
	return militaryTheoryTypeLabels[type];
}

function selectedAnswerText(question: MilitaryTheoryQuestion) {
	if (question.type === "fill") return savedRecord?.text || fillInput;
	if (question.type === "judge") return savedRecord?.values?.[0] || selectedKeys[0] || "";
	return (savedRecord?.values ?? selectedKeys).join("");
}

function correctAnswerText(question: MilitaryTheoryQuestion) {
	if (question.type === "single" || question.type === "multiple") {
		return question.answerKeys?.join("") ?? "";
	}
	return question.answerText;
}

function getFillHint(question: MilitaryTheoryQuestion) {
	const answerCount = question.answers?.length ?? 0;
	if (question.answers?.some((answer) => normalizeAnswer(answer) === "c4kisr")) {
		return "由于输入格式可能会出错，直接给出答案：C^4KISR。";
	}
	if (answerCount > 1) {
		return `本题有 ${answerCount} 个空，多个答案之间请使用中文分号；隔开。`;
	}
	return "填写答案后提交。";
}

function getChoiceClass(key: string) {
	if (!currentQuestion) return "option";
	const savedValues = savedRecord?.values ?? selectedKeys;
	const correctKeys = currentQuestion.answerKeys ?? [];
	if (!resolvedSubmitted) {
		return savedValues.includes(key) ? "option selected" : "option";
	}
	if (correctKeys.includes(key)) return "option correct";
	if (savedValues.includes(key) && !correctKeys.includes(key)) return "option wrong";
	return "option muted";
}

function getJudgeClass(value: string) {
	const chosen = savedRecord?.values?.[0] ?? selectedKeys[0] ?? "";
	if (!resolvedSubmitted) return chosen === value ? "judge-choice selected" : "judge-choice";
	if (value === currentQuestion?.answerText) return "judge-choice correct";
	if (chosen === value && value !== currentQuestion?.answerText) return "judge-choice wrong";
	return "judge-choice muted";
}

function handleKeydown(event: KeyboardEvent) {
	const target = event.target;
	if (
		target instanceof HTMLInputElement ||
		target instanceof HTMLTextAreaElement ||
		target instanceof HTMLSelectElement ||
		(target instanceof HTMLElement && target.isContentEditable)
	) {
		return;
	}
	if (!currentQuestion) return;

	const key = event.key.toUpperCase();
	if (
		(currentQuestion.type === "single" || currentQuestion.type === "multiple") &&
		/^[A-F]$/u.test(key)
	) {
		toggleKey(key);
		return;
	}
	if (currentQuestion.type === "judge" && (event.key === "1" || event.key === "2")) {
		toggleKey(event.key === "1" ? "对" : "错");
		return;
	}
	if (event.key === "Enter") {
		if (!resolvedSubmitted) submitAnswer();
		else nextQuestion();
		return;
	}
	if (event.key === "ArrowRight") nextQuestion();
	if (event.key === "ArrowLeft") previousQuestion();
}
</script>

<svelte:head>
	<title>军事理论刷题模式</title>
</svelte:head>

<svelte:window on:keydown={handleKeydown} />

<section class="military-shell">
	<header class="dashboard-head">
		<div>
			<div class="eyebrow">Military Theory Review</div>
			<h1>军事理论刷题</h1>
		</div>
		<div class="head-stats" aria-label="题库统计">
			<div>
				<strong>{questions.length}</strong>
				<span>题目</span>
			</div>
			<div>
				<strong>{wrongIds.length}</strong>
				<span>待复习</span>
			</div>
			<div>
				<strong>{knowledge.length}</strong>
				<span>知识点</span>
			</div>
		</div>
	</header>

	<div class="view-tabs" aria-label="页面模式">
		<button type="button" class:active={view === "practice"} on:click={() => changeView("practice")}>
			<Icon icon="material-symbols:quiz-outline-rounded" class="button-icon" />
			刷题
		</button>
		<button type="button" class:active={view === "knowledge"} on:click={() => changeView("knowledge")}>
			<Icon icon="material-symbols:menu-book-outline-rounded" class="button-icon" />
			知识点
		</button>
	</div>

	<div class="filter-panel">
		<div class="chapter-tabs" aria-label="章节筛选">
			{#each chapterFilters as chapter}
				<button
					type="button"
					class:active={chapterFilter === chapter.value}
					on:click={() => changeChapter(chapter.value)}
				>
					{chapter.label}
				</button>
			{/each}
		</div>

		{#if view === "practice"}
			<div class="type-tabs" aria-label="题型筛选">
				{#each typeFilters as type}
					<button
						type="button"
						class:active={typeFilter === type.value}
						on:click={() => changeType(type.value)}
					>
						{type.label}
					</button>
				{/each}
			</div>
		{/if}
	</div>

	{#if view === "practice"}
		<div class="mode-tabs" aria-label="刷题范围">
			<button type="button" class:active={mode === "all"} on:click={() => changeMode("all")}>
				<Icon icon="material-symbols:library-books-outline-rounded" class="button-icon" />
				全部
			</button>
			<button type="button" class:active={mode === "wrong"} on:click={() => changeMode("wrong")}>
				<Icon icon="material-symbols:error-outline-rounded" class="button-icon" />
				待复习
			</button>
			<button type="button" class:active={mode === "starred"} on:click={() => changeMode("starred")}>
				<Icon icon="material-symbols:kid-star-outline-rounded" class="button-icon" />
				收藏
			</button>
		</div>

		<div class="practice-layout">
			<aside class="side-panel">
				<div class="progress-block">
					<div class="progress-title">
						<span>当前进度</span>
						<strong>{progressPercent}%</strong>
					</div>
					<div class="progress-track">
						<div style={`width: ${progressPercent}%`}></div>
					</div>
					<div class="progress-meta">
						<span>{visibleQuestions.length ? currentIndex + 1 : 0} / {visibleQuestions.length}</span>
						<span>已答 {answeredInScope}</span>
					</div>
				</div>

				<div class="mini-stats">
					<div>
						<span>正确率</span>
						<strong>{sessionTotal ? `${accuracy}%` : "--"}</strong>
					</div>
					<div>
						<span>本次</span>
						<strong>{sessionTotal}</strong>
					</div>
				</div>

				<div class="tool-grid">
					<button
						type="button"
						class:active-tool={order === "sequential"}
						on:click={() => changeOrder("sequential")}
					>
						<Icon icon="material-symbols:sort-rounded" class="button-icon" />
						顺序
					</button>
					<button
						type="button"
						class:active-tool={order === "random"}
						on:click={() => changeOrder("random")}
					>
						<Icon icon="material-symbols:shuffle-rounded" class="button-icon" />
						乱序
					</button>
					<button type="button" on:click={reshuffle}>
						<Icon icon="material-symbols:casino-outline-rounded" class="button-icon" />
						重排
					</button>
					<button type="button" on:click={resetSession}>
						<Icon icon="material-symbols:restart-alt-rounded" class="button-icon" />
						本次清零
					</button>
					<button type="button" on:click={manualSave}>
						<Icon icon="material-symbols:save-outline-rounded" class="button-icon" />
						保存
					</button>
					<button
						type="button"
						class:active-tool={showQuestionList}
						on:click={() => (showQuestionList = !showQuestionList)}
					>
						<Icon icon="material-symbols:format-list-numbered-rounded" class="button-icon" />
						题板
					</button>
					<button type="button" class="danger-tool" on:click={() => resetAll()}>
						<Icon icon="material-symbols:delete-outline-rounded" class="button-icon" />
						清空
					</button>
				</div>

				<div class="save-status" aria-live="polite">
					<Icon icon="material-symbols:cloud-done-outline-rounded" class="button-icon" />
					<span>{saveNotice || "自动保存已开启"}</span>
				</div>

				<div class="bank-meta">
					<div>
						<span>客观题</span>
						<strong>{objectiveCount}</strong>
					</div>
					<div>
						<span>主观题</span>
						<strong>{subjectiveCount}</strong>
					</div>
				</div>

				{#if showQuestionList}
					<div class="question-list-card">
						<div class="list-head">
							<strong>当前题板</strong>
							<span>{visibleQuestions.length} 题</span>
						</div>
						<div class="question-list">
							{#each visibleQuestions as question, index}
								<button
									type="button"
									class:current={index === currentIndex}
									class:answered={Boolean(answered[question.id])}
									class:drafted={Boolean(drafts[question.id]) && !answered[question.id]}
									class:wrong={wrongSet.has(question.id)}
									on:click={() => goToQuestion(index)}
								>
									<span>{index + 1}</span>
									<strong>{typeLabel(question.type)} · {question.chapterTitle} · {question.number}</strong>
									{#if starredSet.has(question.id)}
										<Icon icon="material-symbols:kid-star-rounded" class="list-star" />
									{/if}
								</button>
							{/each}
						</div>
					</div>
				{/if}
			</aside>

			{#if currentQuestion}
				<article class="question-panel">
					<div class="question-head">
						<div>
							<span>{currentQuestion.chapterTitle}</span>
							<strong>{typeLabel(currentQuestion.type)} · 第 {currentQuestion.number} 题</strong>
						</div>
						<button
							type="button"
							class="star-btn"
							class:active={starredSet.has(currentQuestion.id)}
							on:click={toggleStar}
							aria-label="收藏当前题目"
						>
							<Icon
								icon={starredSet.has(currentQuestion.id)
									? "material-symbols:kid-star-rounded"
									: "material-symbols:kid-star-outline-rounded"}
								class="star-icon"
							/>
						</button>
					</div>

					<p class="question-text">{currentQuestion.prompt}</p>

					{#if currentQuestion.type === "single" || currentQuestion.type === "multiple"}
						{#if currentQuestion.type === "multiple"}
							<div class="multi-hint" aria-live="polite">
								<span>多选题</span>
								<strong>{selectedKeys.length ? `已选 ${selectedKeys.join("、")}` : "未选择"}</strong>
							</div>
						{/if}
						<div class="options" class:multi-options={currentQuestion.type === "multiple"}>
							{#each currentQuestion.options ?? [] as option}
								<button
									type="button"
									class={getChoiceClass(option.key)}
									class:multi-option={currentQuestion.type === "multiple"}
									on:click={() => toggleKey(option.key)}
									aria-pressed={(savedRecord?.values ?? selectedKeys).includes(option.key)}
								>
									<span>{option.key}</span>
									<strong>{option.text}</strong>
								</button>
							{/each}
						</div>
					{/if}

					{#if currentQuestion.type === "judge"}
						<div class="judge-grid">
							<button type="button" class={getJudgeClass("对")} on:click={() => toggleKey("对")}>
								<span>对</span>
								<strong>正确</strong>
							</button>
							<button type="button" class={getJudgeClass("错")} on:click={() => toggleKey("错")}>
								<span>错</span>
								<strong>错误</strong>
							</button>
						</div>
					{/if}

					{#if currentQuestion.type === "fill"}
						<label class="answer-input">
							<span>填写答案</span>
							<textarea
								bind:value={fillInput}
								rows="3"
								disabled={resolvedSubmitted}
								placeholder="多个答案请用中文分号；隔开"
							></textarea>
							<small>{getFillHint(currentQuestion)}</small>
						</label>
					{/if}

					{#if currentQuestion.type === "short" || currentQuestion.type === "essay"}
						<label class="answer-input">
							<span>我的要点</span>
							<textarea bind:value={writtenAnswer} rows="6"></textarea>
						</label>
					{/if}

					<div class="answer-actions">
						<button type="button" class="nav-btn" on:click={previousQuestion} disabled={currentIndex === 0}>
							<Icon icon="material-symbols:chevron-left-rounded" class="button-icon" />
							上一题
						</button>
						<button
							type="button"
							class="submit-btn"
							on:click={submitAnswer}
							disabled={!canSubmitCurrent}
						>
							{#if currentQuestion.type === "short" || currentQuestion.type === "essay"}
								{showAnswer ? "要点已展开" : "查看答案要点"}
							{:else}
								{resolvedSubmitted ? "已提交" : "提交答案"}
							{/if}
						</button>
						<button
							type="button"
							class="nav-btn"
							on:click={nextQuestion}
							disabled={currentIndex >= visibleQuestions.length - 1}
						>
							下一题
							<Icon icon="material-symbols:chevron-right-rounded" class="button-icon" />
						</button>
					</div>

					{#if resolvedSubmitted && isObjectiveMilitaryQuestion(currentQuestion)}
						<div class:result-correct={savedRecord?.correct} class:result-wrong={!savedRecord?.correct} class="result-banner">
							<Icon
								icon={savedRecord?.correct
									? "material-symbols:check-circle-rounded"
									: "material-symbols:cancel-rounded"}
								class="result-icon"
							/>
							<div>
								<strong>{savedRecord?.correct ? "回答正确" : "回答错误"}</strong>
								<span>你的答案：{selectedAnswerText(currentQuestion)} · 正确答案：{correctAnswerText(currentQuestion)}</span>
							</div>
							<button type="button" on:click={retryQuestion}>重做</button>
						</div>
					{/if}

					{#if resolvedSubmitted && !isObjectiveMilitaryQuestion(currentQuestion)}
						<div class:result-correct={savedRecord?.self === "known"} class:result-wrong={savedRecord?.self === "review"} class="result-banner">
							<Icon
								icon={savedRecord?.self === "known"
									? "material-symbols:check-circle-rounded"
									: "material-symbols:bookmark-alert-outline-rounded"}
								class="result-icon"
							/>
							<div>
								<strong>{savedRecord?.self === "known" ? "已标记掌握" : "已加入待复习"}</strong>
								<span>可随时重做并重新标记</span>
							</div>
							<button type="button" on:click={retryQuestion}>重做</button>
						</div>
					{/if}

					{#if showAnswer || resolvedSubmitted}
						<section class="answer-panel">
							<div class="answer-title">
								<Icon icon="material-symbols:fact-check-outline-rounded" class="button-icon" />
								<strong>答案</strong>
							</div>

							{#if currentQuestion.type === "fill"}
								<p>{currentQuestion.filledPrompt}</p>
							{:else if currentQuestion.type === "single" || currentQuestion.type === "multiple" || currentQuestion.type === "judge"}
								<p>{correctAnswerText(currentQuestion)}</p>
							{:else}
								<ul>
									{#each currentQuestion.answerLines ?? [] as line}
										<li>{line}</li>
									{/each}
								</ul>
								<div class="self-actions">
									<button type="button" on:click={() => markSubjective("known")}>
										<Icon icon="material-symbols:check-rounded" class="button-icon" />
										掌握
									</button>
									<button type="button" on:click={() => markSubjective("review")}>
										<Icon icon="material-symbols:bookmark-alert-outline-rounded" class="button-icon" />
										待复习
									</button>
								</div>
							{/if}
						</section>
					{/if}
				</article>
			{:else}
				<section class="empty-panel">
					<Icon icon="material-symbols:quiz-outline-rounded" class="empty-icon" />
					<h2>当前范围没有题目</h2>
					<button type="button" on:click={() => changeMode("all")}>回到全部</button>
				</section>
			{/if}
		</div>
	{:else}
		<section class="knowledge-section">
			<div class="knowledge-tools">
				<label>
					<Icon icon="material-symbols:search-rounded" class="button-icon" />
					<input bind:value={search} type="search" />
				</label>
				<span>{filteredKnowledge.length} 条</span>
			</div>

			<div class="knowledge-grid">
				{#each filteredKnowledge as item}
					<article class="knowledge-card">
						<div class="knowledge-card-head">
							<span>{item.chapterTitle}</span>
							<strong>{item.kind}</strong>
						</div>
						<h2>{item.title}</h2>
						{#if item.body}
							<p>{item.body}</p>
						{/if}
						{#if item.points.length}
							<ul>
								{#each item.points as point}
									<li>{point}</li>
								{/each}
							</ul>
						{/if}
						<button type="button" on:click={() => startChapterPractice(item.chapter)}>
							<Icon icon="material-symbols:play-arrow-rounded" class="button-icon" />
							刷本章
						</button>
					</article>
				{/each}
			</div>
		</section>
	{/if}
</section>

<style>
	.military-shell {
		--panel: rgba(24, 27, 23, 0.78);
		--panel-strong: rgba(17, 20, 18, 0.9);
		--line: rgba(232, 224, 202, 0.16);
		--text: #f7f4ec;
		--soft: rgba(245, 239, 225, 0.86);
		--muted: rgba(218, 208, 184, 0.72);
		--accent: #d8a838;
		--accent-2: #83b350;
		--danger: #f87171;
		--success: #4ade80;
		min-height: calc(100vh - 7rem);
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background:
			linear-gradient(135deg, rgba(38, 45, 34, 0.88), rgba(16, 18, 17, 0.88)),
			rgba(22, 24, 22, 0.86);
		padding: 1rem;
		color: var(--text);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
	}

	button,
	input,
	textarea {
		font: inherit;
		letter-spacing: 0;
	}

	button {
		border: 0;
		cursor: pointer;
	}

	.dashboard-head {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1rem;
		margin-bottom: 0.85rem;
	}

	.eyebrow {
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 850;
		letter-spacing: 0.08em;
		text-transform: uppercase;
	}

	h1 {
		margin: 0.2rem 0 0;
		color: var(--text);
		font-size: clamp(1.8rem, 4vw, 2.5rem);
		font-weight: 950;
		letter-spacing: 0;
		line-height: 1.12;
	}

	.head-stats,
	.mini-stats,
	.bank-meta {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 0.55rem;
	}

	.head-stats > div,
	.mini-stats > div,
	.bank-meta > div,
	.progress-block {
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(15, 18, 16, 0.44);
		padding: 0.75rem;
	}

	.head-stats strong,
	.mini-stats strong,
	.bank-meta strong {
		display: block;
		color: var(--text);
		font-size: 1.35rem;
		line-height: 1;
	}

	.head-stats span,
	.mini-stats span,
	.bank-meta span {
		display: block;
		margin-top: 0.3rem;
		color: var(--muted);
		font-size: 0.76rem;
		font-weight: 800;
	}

	.view-tabs,
	.mode-tabs,
	.filter-panel {
		margin-bottom: 0.75rem;
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(11, 13, 12, 0.34);
		padding: 0.65rem;
	}

	.view-tabs,
	.mode-tabs,
	.chapter-tabs,
	.type-tabs {
		display: flex;
		flex-wrap: wrap;
		gap: 0.45rem;
	}

	.filter-panel {
		display: grid;
		gap: 0.6rem;
	}

	.view-tabs button,
	.mode-tabs button,
	.chapter-tabs button,
	.type-tabs button,
	.tool-grid button,
	.nav-btn,
	.submit-btn,
	.self-actions button,
	.knowledge-card button,
	.empty-panel button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.4rem;
		min-height: 2.45rem;
		border: 1px solid rgba(232, 224, 202, 0.11);
		border-radius: 0.5rem;
		background: rgba(233, 223, 198, 0.09);
		color: var(--soft);
		font-weight: 820;
		transition:
			background-color 160ms ease,
			border-color 160ms ease,
			color 160ms ease,
			transform 160ms ease;
	}

	.view-tabs button,
	.mode-tabs button,
	.chapter-tabs button,
	.type-tabs button {
		padding: 0 0.75rem;
	}

	.button-icon {
		font-size: 1.1rem;
	}

	.view-tabs button:hover,
	.mode-tabs button:hover,
	.chapter-tabs button:hover,
	.type-tabs button:hover,
	.tool-grid button:hover,
	.nav-btn:hover,
	.self-actions button:hover,
	.knowledge-card button:hover,
	.empty-panel button:hover {
		border-color: rgba(216, 168, 56, 0.45);
		background: rgba(216, 168, 56, 0.13);
		color: var(--text);
	}

	.view-tabs button.active,
	.mode-tabs button.active,
	.chapter-tabs button.active,
	.type-tabs button.active,
	.tool-grid button.active-tool,
	.submit-btn {
		border-color: rgba(216, 168, 56, 0.58);
		background:
			linear-gradient(135deg, rgba(216, 168, 56, 0.25), rgba(131, 179, 80, 0.16)),
			rgba(17, 20, 18, 0.7);
		color: var(--text);
		box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.04);
	}

	.practice-layout {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 0.85rem;
	}

	.side-panel,
	.question-panel,
	.empty-panel,
	.knowledge-section {
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background:
			linear-gradient(135deg, rgba(27, 31, 26, 0.72), rgba(12, 14, 13, 0.66)),
			var(--panel);
	}

	.side-panel {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		padding: 0.85rem;
	}

	.progress-title,
	.progress-meta {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.7rem;
	}

	.progress-title span,
	.progress-meta {
		color: var(--muted);
		font-size: 0.8rem;
		font-weight: 820;
	}

	.progress-title strong {
		color: var(--text);
		font-size: 1.3rem;
	}

	.progress-track {
		overflow: hidden;
		height: 0.52rem;
		margin: 0.7rem 0;
		border-radius: 999px;
		background: rgba(232, 224, 202, 0.13);
	}

	.progress-track > div {
		height: 100%;
		border-radius: inherit;
		background: linear-gradient(90deg, var(--accent), var(--accent-2));
		transition: width 220ms ease;
	}

	.mini-stats,
	.bank-meta {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.tool-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 0.5rem;
	}

	.tool-grid button {
		padding: 0 0.5rem;
	}

	.tool-grid button.danger-tool {
		border-color: rgba(248, 113, 113, 0.22);
		background: rgba(127, 29, 29, 0.22);
		color: rgba(254, 202, 202, 0.92);
	}

	.save-status {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.42rem;
		min-height: 2.2rem;
		border: 1px solid rgba(74, 222, 128, 0.18);
		border-radius: 0.5rem;
		background: rgba(22, 101, 52, 0.16);
		color: rgba(187, 247, 208, 0.9);
		font-size: 0.8rem;
		font-weight: 840;
		text-align: center;
	}

	.save-status span {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.question-list-card {
		display: grid;
		gap: 0.65rem;
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(10, 12, 11, 0.32);
		padding: 0.7rem;
	}

	.list-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.7rem;
	}

	.list-head strong {
		color: var(--text);
		font-size: 0.92rem;
	}

	.list-head span {
		color: var(--muted);
		font-size: 0.76rem;
		font-weight: 820;
	}

	.question-list {
		display: grid;
		gap: 0.4rem;
		max-height: 22rem;
		overflow-y: auto;
		padding-right: 0.2rem;
	}

	.question-list button {
		display: grid;
		grid-template-columns: 2rem minmax(0, 1fr) auto;
		align-items: center;
		gap: 0.5rem;
		min-height: 2.45rem;
		border: 1px solid rgba(232, 224, 202, 0.1);
		border-radius: 0.5rem;
		background: rgba(233, 223, 198, 0.07);
		padding: 0.35rem 0.5rem;
		color: var(--soft);
		text-align: left;
	}

	.question-list button:hover,
	.question-list button.current {
		border-color: rgba(216, 168, 56, 0.55);
		background: rgba(216, 168, 56, 0.14);
		color: var(--text);
	}

	.question-list button.answered:not(.current) {
		border-color: rgba(74, 222, 128, 0.22);
	}

	.question-list button.drafted:not(.current) {
		border-color: rgba(216, 168, 56, 0.32);
		background: rgba(216, 168, 56, 0.09);
	}

	.question-list button.wrong:not(.current) {
		border-color: rgba(248, 113, 113, 0.42);
		background: rgba(127, 29, 29, 0.18);
	}

	.question-list button span {
		display: grid;
		place-items: center;
		width: 2rem;
		height: 1.8rem;
		border-radius: 0.4rem;
		background: rgba(233, 223, 198, 0.11);
		color: var(--text);
		font-size: 0.76rem;
		font-weight: 920;
	}

	.question-list button strong {
		overflow: hidden;
		color: inherit;
		font-size: 0.8rem;
		font-weight: 800;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.list-star {
		color: #facc15;
		font-size: 1rem;
	}

	.question-panel {
		min-height: 32rem;
		padding: 1rem;
	}

	.question-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin-bottom: 0.9rem;
	}

	.question-head span {
		display: inline-flex;
		margin-bottom: 0.3rem;
		color: var(--accent);
		font-size: 0.78rem;
		font-weight: 900;
	}

	.question-head strong {
		display: block;
		color: var(--text);
		font-size: 1.15rem;
	}

	.star-btn {
		display: grid;
		place-items: center;
		width: 2.6rem;
		height: 2.6rem;
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(233, 223, 198, 0.09);
		color: var(--muted);
	}

	.star-btn.active {
		color: #facc15;
		background: rgba(250, 204, 21, 0.14);
	}

	.star-icon {
		font-size: 1.35rem;
	}

	.question-text {
		margin: 0 0 1rem;
		color: var(--text);
		font-size: clamp(1.05rem, 1.65vw, 1.2rem);
		font-weight: 760;
		line-height: 1.8;
		word-break: break-word;
	}

	.options,
	.judge-grid {
		display: grid;
		gap: 0.62rem;
	}

	.options.multi-options {
		grid-template-columns: repeat(auto-fit, minmax(min(100%, 20rem), 1fr));
		align-items: stretch;
	}

	.multi-hint {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 0.45rem;
		margin: -0.15rem 0 0.7rem;
		border: 1px solid rgba(216, 168, 56, 0.18);
		border-radius: 0.5rem;
		background: rgba(216, 168, 56, 0.09);
		padding: 0.55rem 0.65rem;
		color: var(--muted);
	}

	.multi-hint span,
	.multi-hint strong {
		font-size: 0.8rem;
		font-weight: 880;
		line-height: 1.4;
	}

	.multi-hint strong {
		min-width: 0;
		color: var(--text);
		overflow-wrap: anywhere;
	}

	.option,
	.judge-choice {
		position: relative;
		display: grid;
		align-items: center;
		gap: 0.7rem;
		width: 100%;
		min-width: 0;
		min-height: 3.4rem;
		border: 1px solid rgba(232, 224, 202, 0.12);
		border-radius: 0.5rem;
		background: rgba(13, 16, 14, 0.46);
		padding: 0.7rem;
		color: var(--soft);
		text-align: left;
	}

	.option {
		grid-template-columns: 2.15rem minmax(0, 1fr);
	}

	.option.multi-option {
		align-items: start;
		min-height: 4rem;
	}

	.judge-choice {
		grid-template-columns: 2.4rem minmax(0, 1fr);
	}

	.option span,
	.judge-choice span {
		display: grid;
		place-items: center;
		flex: 0 0 auto;
		width: 2.15rem;
		height: 2.15rem;
		border-radius: 0.42rem;
		background: rgba(233, 223, 198, 0.12);
		color: var(--text);
		font-weight: 930;
	}

	.option strong,
	.judge-choice strong {
		min-width: 0;
		color: inherit;
		font-size: 0.98rem;
		font-weight: 760;
		line-height: 1.45;
		word-break: break-word;
		overflow-wrap: anywhere;
	}

	.option:hover,
	.judge-choice:hover,
	.option.selected,
	.judge-choice.selected {
		border-color: rgba(216, 168, 56, 0.58);
		background:
			linear-gradient(135deg, rgba(216, 168, 56, 0.16), rgba(131, 179, 80, 0.09)),
			rgba(233, 223, 198, 0.09);
		color: var(--text);
	}

	.option.selected,
	.judge-choice.selected {
		box-shadow:
			inset 0 0 0 1px rgba(247, 223, 126, 0.28),
			0 0 0 1px rgba(216, 168, 56, 0.12);
	}

	.option.selected span,
	.judge-choice.selected span {
		background: rgba(216, 168, 56, 0.28);
		box-shadow: inset 0 0 0 1px rgba(247, 223, 126, 0.48);
	}

	.option.correct,
	.judge-choice.correct {
		border-color: rgba(74, 222, 128, 0.72);
		background: rgba(22, 101, 52, 0.27);
	}

	.option.wrong,
	.judge-choice.wrong {
		border-color: rgba(248, 113, 113, 0.76);
		background: rgba(127, 29, 29, 0.27);
	}

	.option.muted,
	.judge-choice.muted {
		opacity: 0.56;
	}

	.answer-input {
		display: grid;
		gap: 0.45rem;
		margin-top: 0.8rem;
	}

	.answer-input span {
		color: var(--accent);
		font-size: 0.8rem;
		font-weight: 900;
	}

	.answer-input small {
		color: var(--muted);
		font-size: 0.78rem;
		font-weight: 760;
		line-height: 1.55;
	}

	.answer-input textarea,
	.knowledge-tools input {
		width: 100%;
		border: 1px solid rgba(232, 224, 202, 0.14);
		border-radius: 0.5rem;
		background: rgba(8, 10, 9, 0.56);
		color: var(--text);
		outline: none;
	}

	.answer-input textarea {
		min-height: 6rem;
		resize: vertical;
		padding: 0.85rem;
		line-height: 1.65;
	}

	.answer-input textarea:focus,
	.knowledge-tools input:focus {
		border-color: rgba(216, 168, 56, 0.58);
		box-shadow: 0 0 0 3px rgba(216, 168, 56, 0.12);
	}

	.answer-actions {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.65rem;
		margin-top: 0.9rem;
	}

	.nav-btn,
	.submit-btn {
		padding: 0 0.9rem;
	}

	button:disabled,
	textarea:disabled {
		cursor: not-allowed;
		opacity: 0.58;
	}

	.result-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 0.8rem;
		margin-top: 0.9rem;
		border-radius: 0.5rem;
		padding: 0.85rem;
	}

	.result-banner > div {
		flex: 1 1 14rem;
	}

	.result-banner button {
		min-height: 2.25rem;
		border-radius: 0.45rem;
		background: rgba(255, 255, 255, 0.1);
		color: var(--soft);
		padding: 0 0.75rem;
		font-weight: 830;
	}

	.result-icon {
		font-size: 1.75rem;
	}

	.result-banner strong,
	.result-banner span {
		display: block;
	}

	.result-banner strong {
		color: var(--text);
	}

	.result-banner span {
		margin-top: 0.16rem;
		color: var(--muted);
		font-size: 0.86rem;
		line-height: 1.5;
	}

	.result-correct {
		background: rgba(22, 101, 52, 0.28);
		color: #86efac;
	}

	.result-wrong {
		background: rgba(127, 29, 29, 0.28);
		color: #fca5a5;
	}

	.answer-panel {
		margin-top: 0.9rem;
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(8, 10, 9, 0.34);
		padding: 0.85rem;
	}

	.answer-title {
		display: flex;
		align-items: center;
		gap: 0.45rem;
		color: var(--accent);
		font-weight: 900;
	}

	.answer-panel p {
		margin: 0.55rem 0 0;
		color: var(--soft);
		line-height: 1.75;
	}

	.answer-panel ul,
	.knowledge-card ul {
		margin: 0.65rem 0 0;
		padding-left: 1.15rem;
		color: var(--soft);
		line-height: 1.75;
	}

	.self-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-top: 0.8rem;
	}

	.self-actions button {
		padding: 0 0.85rem;
	}

	.empty-panel {
		display: grid;
		place-items: center;
		min-height: 24rem;
		padding: 2rem;
		text-align: center;
	}

	.empty-icon {
		color: var(--accent);
		font-size: 3rem;
	}

	.empty-panel h2 {
		margin: 0.8rem 0;
		color: var(--text);
	}

	.empty-panel button {
		padding: 0 1rem;
	}

	.knowledge-section {
		padding: 0.85rem;
	}

	.knowledge-tools {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 0.75rem;
		margin-bottom: 0.85rem;
	}

	.knowledge-tools label {
		display: grid;
		grid-template-columns: auto minmax(12rem, 24rem);
		align-items: center;
		gap: 0.45rem;
		color: var(--accent);
	}

	.knowledge-tools input {
		min-height: 2.45rem;
		padding: 0 0.75rem;
	}

	.knowledge-tools span {
		color: var(--muted);
		font-weight: 840;
	}

	.knowledge-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(min(100%, 18rem), 1fr));
		gap: 0.75rem;
	}

	.knowledge-card {
		border: 1px solid var(--line);
		border-radius: 0.5rem;
		background: rgba(13, 16, 14, 0.46);
		padding: 0.85rem;
	}

	.knowledge-card-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.7rem;
	}

	.knowledge-card-head span,
	.knowledge-card-head strong {
		color: var(--accent);
		font-size: 0.76rem;
		font-weight: 900;
	}

	.knowledge-card h2 {
		margin: 0.45rem 0 0;
		color: var(--text);
		font-size: 1rem;
		line-height: 1.5;
	}

	.knowledge-card p {
		margin: 0.55rem 0 0;
		color: var(--soft);
		line-height: 1.72;
	}

	.knowledge-card button {
		margin-top: 0.75rem;
		padding: 0 0.8rem;
	}

	:global(:root:not(.dark)) .military-shell {
		color: var(--text);
	}

	@media (max-width: 520px) {
		.military-shell {
			padding: 0.75rem;
		}

		.head-stats,
		.mini-stats,
		.bank-meta {
			gap: 0.45rem;
		}

		.tool-grid {
			gap: 0.45rem;
		}

		.tool-grid button {
			min-width: 0;
			min-height: 2.55rem;
			padding: 0 0.35rem;
			font-size: 0.82rem;
			white-space: normal;
		}

		.question-panel {
			min-height: 28rem;
			padding: 0.82rem;
		}

		.question-head {
			align-items: flex-start;
			gap: 0.75rem;
		}

		.question-head strong {
			font-size: 1rem;
			line-height: 1.35;
		}

		.options.multi-options {
			grid-template-columns: minmax(0, 1fr);
		}

		.multi-hint {
			align-items: flex-start;
			flex-direction: column;
			gap: 0.22rem;
		}

		.option,
		.judge-choice {
			grid-template-columns: 2rem minmax(0, 1fr);
			gap: 0.58rem;
			min-height: 3.25rem;
			padding: 0.62rem;
		}

		.option span,
		.judge-choice span {
			width: 2rem;
			height: 2rem;
		}

		.option strong,
		.judge-choice strong {
			font-size: 0.94rem;
			line-height: 1.52;
		}

		.answer-actions {
			gap: 0.5rem;
		}

		.knowledge-tools label {
			grid-template-columns: auto minmax(0, 1fr);
			width: 100%;
		}
	}

	@media (min-width: 768px) {
		.military-shell {
			padding: 1.25rem;
		}

		.dashboard-head {
			grid-template-columns: minmax(0, 1fr) 20rem;
			align-items: end;
		}

		.answer-actions {
			grid-template-columns: 1fr 1.3fr 1fr;
		}

		.judge-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	@media (min-width: 1024px) {
		.practice-layout {
			grid-template-columns: 17.5rem minmax(0, 1fr);
			align-items: start;
		}

		.side-panel {
			position: sticky;
			top: 6rem;
		}

		.question-panel {
			padding: 1.35rem;
		}
	}
</style>
