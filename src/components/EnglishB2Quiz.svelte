<script lang="ts">
import Icon from "@iconify/svelte";
import { onMount } from "svelte";
import type {
	EnglishB2OptionKey,
	EnglishB2Question,
} from "../utils/english-b2-quiz";

export let questions: EnglishB2Question[] = [];

type Mode = "all" | "wrong" | "starred";
type Order = "sequential" | "random";

const storageKey = "drawrain-english-b2-quiz-v1";
const validUnitFilters = new Set(["all", "1", "2", "3", "4", "5"]);
const validModes = new Set<Mode>(["all", "wrong", "starred"]);
const validOrders = new Set<Order>(["sequential", "random"]);
const unitFilters = [
	{ value: "all", label: "全部" },
	{ value: "1", label: "B2U1" },
	{ value: "2", label: "B2U2" },
	{ value: "3", label: "B2U3" },
	{ value: "4", label: "B2U4" },
	{ value: "5", label: "B2U5" },
] as const;

let unitFilter = "all";
let mode: Mode = "all";
let order: Order = "sequential";
let currentIndex = 0;
let selected: EnglishB2OptionKey | "" = "";
let submitted = false;
let showAnalysis = false;
let showTranslation = true;
let showQuestionList = false;
let answered: Record<string, EnglishB2OptionKey> = {};
let wrongIds: string[] = [];
let starredIds: string[] = [];
let sessionCorrect = 0;
let sessionTotal = 0;
let orderSeed = 0;
let mounted = false;
let clearedWrongIds: string[] = [];

$: wrongSet = new Set(wrongIds);
$: starredSet = new Set(starredIds);
$: questionIds = new Set(questions.map((question) => question.id));
$: questionAnswerMap = new Map(
	questions.map((question) => [question.id, question.answer] as const),
);
$: visibleQuestions = buildVisibleQuestions(
	questions,
	unitFilter,
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
$: savedAnswer = currentQuestion ? answered[currentQuestion.id] ?? "" : "";
$: progressPercent =
	visibleQuestions.length > 0
		? Math.round(((currentIndex + 1) / visibleQuestions.length) * 100)
		: 0;
$: answeredInScope = visibleQuestions.filter((question) => answered[question.id]).length;
$: accuracy =
	sessionTotal > 0 ? Math.round((sessionCorrect / sessionTotal) * 100) : 0;
$: currentAnswer = currentQuestion ? savedAnswer || selected : "";
$: resolvedSubmitted = submitted || Boolean(savedAnswer);
$: isCorrect =
	currentQuestion && currentAnswer
		? currentAnswer === currentQuestion.answer
		: false;
$: selectedOption = currentQuestion
	? currentQuestion.options.find((option) => option.key === selected)
	: null;

onMount(() => {
	const saved = loadSavedState();
	if (saved) {
		try {
			const parsed = JSON.parse(saved);
			const nextAnswered = sanitizeAnswered(parsed.answered);
			answered = nextAnswered;
			wrongIds = sanitizeWrongIds(parsed.wrongIds, nextAnswered);
			starredIds = sanitizeIds(parsed.starredIds);
			unitFilter = validUnitFilters.has(parsed.unitFilter) ? parsed.unitFilter : "all";
			mode = validModes.has(parsed.mode) ? parsed.mode : "all";
			order = validOrders.has(parsed.order) ? parsed.order : "sequential";
			currentIndex = Number.isFinite(parsed.currentIndex)
				? Math.max(0, parsed.currentIndex)
				: 0;
			showTranslation = parsed.showTranslation ?? true;
			showQuestionList = parsed.showQuestionList ?? false;
			orderSeed = Number.isFinite(parsed.orderSeed) ? parsed.orderSeed : 0;
		} catch {
			resetAll(false);
		}
	}
	mounted = true;
});

$: if (mounted) {
	saveState();
}

function loadSavedState() {
	try {
		return localStorage.getItem(storageKey);
	} catch {
		return null;
	}
}

function saveState() {
	try {
		localStorage.setItem(
			storageKey,
			JSON.stringify({
				answered,
				wrongIds,
				starredIds,
				unitFilter,
				mode,
				order,
				currentIndex,
				showTranslation,
				showQuestionList,
				orderSeed,
			}),
		);
	} catch {
		// Some privacy modes block localStorage. The quiz should still work in memory.
	}
}

function buildVisibleQuestions(
	source: EnglishB2Question[],
	unit: string,
	selectedMode: Mode,
	wrong: Set<string>,
	starred: Set<string>,
	selectedOrder: Order,
	seed: number,
) {
	let list = source;
	if (unit !== "all") {
		list = list.filter((question) => String(question.unit) === unit);
	}
	if (selectedMode === "wrong") {
		list = list.filter((question) => wrong.has(question.id));
	}
	if (selectedMode === "starred") {
		list = list.filter((question) => starred.has(question.id));
	}
	if (selectedOrder === "random") {
		return shuffleQuestions(list, seed || 9527);
	}
	return list;
}

function sanitizeIds(value: unknown) {
	if (!Array.isArray(value)) return [];
	return value.filter((id): id is string => typeof id === "string" && questionIds.has(id));
}

function sanitizeAnswered(value: unknown) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return {};
	const entries = Object.entries(value).filter(([id, answer]) => {
		return (
			questionIds.has(id) &&
			typeof answer === "string" &&
			(answer === "A" || answer === "B" || answer === "C" || answer === "D")
		);
	});
	return Object.fromEntries(entries) as Record<string, EnglishB2OptionKey>;
}

function sanitizeWrongIds(
	value: unknown,
	savedAnswered: Record<string, EnglishB2OptionKey>,
) {
	const ids = sanitizeIds(value);
	return ids.filter((id) => {
		const correctAnswer = questionAnswerMap.get(id);
		return !correctAnswer || savedAnswered[id] !== correctAnswer;
	});
}

function shuffleQuestions(source: EnglishB2Question[], seed: number) {
	const list = [...source];
	let state = seed || 9527;
	for (let index = list.length - 1; index > 0; index--) {
		state = (state * 9301 + 49297) % 233280;
		const target = Math.floor((state / 233280) * (index + 1));
		[list[index], list[target]] = [list[target], list[index]];
	}
	return list;
}

function selectOption(key: EnglishB2OptionKey) {
	if (submitted || savedAnswer || !currentQuestion) return;
	selected = key;
}

function submitAnswer() {
	if (!currentQuestion || !selected || submitted || savedAnswer) return;
	const nextAnswered = { ...answered, [currentQuestion.id]: selected };
	answered = nextAnswered;
	submitted = true;
	showAnalysis = true;
	sessionTotal += 1;

	if (selected === currentQuestion.answer) {
		sessionCorrect += 1;
		if (mode !== "wrong") {
			wrongIds = wrongIds.filter((id) => id !== currentQuestion.id);
		} else if (!clearedWrongIds.includes(currentQuestion.id)) {
			clearedWrongIds = [...clearedWrongIds, currentQuestion.id];
		}
	} else if (!wrongIds.includes(currentQuestion.id)) {
		wrongIds = [...wrongIds, currentQuestion.id];
	}
}

function goToQuestion(index: number) {
	let nextIndex = index;
	const leavingQuestion = currentQuestion;
	const leavingIndex = currentIndex;

	if (leavingQuestion && clearedWrongIds.includes(leavingQuestion.id)) {
		wrongIds = wrongIds.filter((id) => id !== leavingQuestion.id);
		clearedWrongIds = clearedWrongIds.filter((id) => id !== leavingQuestion.id);
		if (nextIndex > leavingIndex) {
			nextIndex -= 1;
		}
	}

	const nextVisibleQuestions = buildVisibleQuestions(
		questions,
		unitFilter,
		mode,
		new Set(wrongIds),
		new Set(starredIds),
		order,
		orderSeed,
	);
	currentIndex = Math.min(Math.max(nextIndex, 0), Math.max(nextVisibleQuestions.length - 1, 0));
	selected = "";
	submitted = false;
	showAnalysis = false;
}

function nextQuestion() {
	if (currentIndex < visibleQuestions.length - 1) {
		goToQuestion(currentIndex + 1);
	}
}

function previousQuestion() {
	if (currentIndex > 0) {
		goToQuestion(currentIndex - 1);
	}
}

function changeUnit(value: string) {
	unitFilter = value;
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

function nextRandomSeed() {
	return (Date.now() + Math.floor(Math.random() * 233280)) % 233280 || 9527;
}

function toggleStar() {
	if (!currentQuestion) return;
	if (starredIds.includes(currentQuestion.id)) {
		starredIds = starredIds.filter((id) => id !== currentQuestion.id);
	} else {
		starredIds = [...starredIds, currentQuestion.id];
	}
}

function resetSession() {
	sessionCorrect = 0;
	sessionTotal = 0;
	selected = "";
	submitted = false;
	showAnalysis = false;
}

function retryQuestion() {
	if (!currentQuestion) return;
	const { [currentQuestion.id]: _removed, ...rest } = answered;
	answered = rest;
	clearedWrongIds = clearedWrongIds.filter((id) => id !== currentQuestion.id);
	if (mode !== "wrong") {
		wrongIds = wrongIds.filter((id) => id !== currentQuestion.id);
	}
	selected = "";
	submitted = false;
	showAnalysis = false;
}

function resetAll(confirmFirst = true) {
	if (confirmFirst && !confirm("清空答题记录、错题和收藏？")) return;
	answered = {};
	wrongIds = [];
	starredIds = [];
	clearedWrongIds = [];
	currentIndex = 0;
	selected = "";
	submitted = false;
	showAnalysis = false;
	sessionCorrect = 0;
	sessionTotal = 0;
}

function getOptionClass(key: EnglishB2OptionKey) {
	if (!currentQuestion) return "option";
	if (!resolvedSubmitted) {
		return selected === key ? "option option-selected" : "option";
	}
	if (key === currentQuestion.answer) return "option option-correct";
	if (key === currentAnswer && key !== currentQuestion.answer) return "option option-wrong";
	return "option option-muted";
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

	const key = event.key.toUpperCase();
	if (key === "A" || key === "B" || key === "C" || key === "D") {
		selectOption(key as EnglishB2OptionKey);
		return;
	}
	if (event.key === "Enter") {
		if (!resolvedSubmitted) {
			submitAnswer();
		} else {
			nextQuestion();
		}
		return;
	}
	if (event.key === "ArrowRight") nextQuestion();
	if (event.key === "ArrowLeft") previousQuestion();
}
</script>

<svelte:head>
	<title>大学英语 B2 刷题模式</title>
</svelte:head>

<svelte:window on:keydown={handleKeydown} />

<section class="quiz-shell content-glass-card">
	<div class="quiz-hero">
		<div>
			<div class="eyebrow">English B2 Training Console</div>
			<h1>大学英语 B2 刷题</h1>
			<p>按单元刷雨课堂词汇题（题目右上角方框可收藏题目）</p>
		</div>
		<div class="hero-stats" aria-label="刷题统计">
			<div>
				<strong>{questions.length}</strong>
				<span>题库总量</span>
			</div>
			<div>
				<strong>{wrongIds.length}</strong>
				<span>错题</span>
			</div>
			<div>
				<strong>{starredIds.length}</strong>
				<span>收藏</span>
			</div>
		</div>
	</div>

	<div class="control-panel">
		<div class="unit-tabs" aria-label="单元筛选">
			{#each unitFilters as unit}
				<button
					type="button"
					class:active={unitFilter === unit.value}
					on:click={() => changeUnit(unit.value)}
				>
					{unit.label}
				</button>
			{/each}
		</div>

		<div class="mode-tabs" aria-label="刷题模式">
			<button type="button" class:active={mode === "all"} on:click={() => changeMode("all")}>
				<Icon icon="material-symbols:library-books-outline-rounded" class="button-icon" />
				全部
			</button>
			<button type="button" class:active={mode === "wrong"} on:click={() => changeMode("wrong")}>
				<Icon icon="material-symbols:error-outline-rounded" class="button-icon" />
				错题
			</button>
			<button
				type="button"
				class:active={mode === "starred"}
				on:click={() => changeMode("starred")}
			>
				<Icon icon="material-symbols:kid-star-outline-rounded" class="button-icon" />
				收藏
			</button>
		</div>
	</div>

	<div class="quiz-layout">
		<aside class="side-panel">
			<div class="progress-card">
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
					<span>本次正确率</span>
					<strong>{sessionTotal ? `${accuracy}%` : "--"}</strong>
				</div>
				<div>
					<span>本次答题</span>
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
					顺序刷题
				</button>
				<button
					type="button"
					class:active-tool={order === "random"}
					on:click={() => changeOrder("random")}
				>
					<Icon icon="material-symbols:shuffle-rounded" class="button-icon" />
					乱序刷题
				</button>
				<button type="button" on:click={reshuffle}>
					<Icon icon="material-symbols:casino-outline-rounded" class="button-icon" />
					重新乱序
				</button>
				<button type="button" on:click={() => (showTranslation = !showTranslation)}>
					<Icon icon="material-symbols:translate-rounded" class="button-icon" />
					{showTranslation ? "译文开" : "译文关"}
				</button>
				<button type="button" on:click={resetSession}>
					<Icon icon="material-symbols:restart-alt-rounded" class="button-icon" />
					本次清零
				</button>
				<button
					type="button"
					class:active-tool={showQuestionList}
					on:click={() => (showQuestionList = !showQuestionList)}
				>
					<Icon icon="material-symbols:format-list-numbered-rounded" class="button-icon" />
					题目列表
				</button>
			</div>

			{#if showQuestionList}
				<div class="question-list-card">
					<div class="question-list-head">
						<strong>当前题板</strong>
						<span>{visibleQuestions.length} 题</span>
					</div>
					<div class="question-list" aria-label="当前全部题目列表">
						{#each visibleQuestions as question, index}
							<button
								type="button"
								class:current={index === currentIndex}
								class:answered={Boolean(answered[question.id])}
								class:wrong={wrongSet.has(question.id)}
								on:click={() => goToQuestion(index)}
							>
								<span>{index + 1}</span>
								<strong>{question.unitCode} · 第 {question.number} 题</strong>
								{#if starredSet.has(question.id)}
									<Icon icon="material-symbols:kid-star-rounded" class="list-star" />
								{/if}
							</button>
						{/each}
					</div>
				</div>
			{/if}

			<button type="button" class="danger-btn" on:click={() => resetAll()}>
				<Icon icon="material-symbols:delete-outline-rounded" class="button-icon" />
				清空记录
			</button>
		</aside>

		{#if currentQuestion}
			<article class="question-card">
				<div class="question-head">
					<div>
						<span>{currentQuestion.unitCode}</span>
						<strong>第 {currentQuestion.number} 题</strong>
					</div>
					<button
						type="button"
						class="star-btn"
						class:active={starredSet.has(currentQuestion.id)}
						on:click={toggleStar}
						aria-label="收藏当前题目"
					>
						<Icon icon={starredSet.has(currentQuestion.id) ? "material-symbols:kid-star-rounded" : "material-symbols:kid-star-outline-rounded"} class="star-icon" />
					</button>
				</div>

				<p class="question-text">{currentQuestion.question}</p>

				<div class="options">
					{#each currentQuestion.options as option}
						<button
							type="button"
							class={getOptionClass(option.key)}
							on:click={() => selectOption(option.key)}
						>
							<span>{option.key}</span>
							<strong>{option.text}</strong>
						</button>
					{/each}
				</div>

				{#if selectedOption && !resolvedSubmitted}
					<div class="selection-banner">
						<Icon icon="material-symbols:ads-click-rounded" class="selection-icon" />
						<div>
							<strong>已选择 {selectedOption.key}</strong>
							<span>{selectedOption.text} · 点击提交后立即判定正确 / 错误</span>
						</div>
					</div>
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
						disabled={!selected || resolvedSubmitted}
					>
						{resolvedSubmitted ? "已提交" : selected ? `确认提交 ${selected}` : "提交答案"}
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

				{#if resolvedSubmitted}
					<div class:result-correct={isCorrect} class:result-wrong={!isCorrect} class="result-banner">
						<Icon icon={isCorrect ? "material-symbols:check-circle-rounded" : "material-symbols:cancel-rounded"} class="result-icon" />
						<div>
							<strong>{isCorrect ? "回答正确" : "回答错误"}</strong>
							<span>你的答案：{currentAnswer} · 正确答案：{currentQuestion.answer}</span>
						</div>
						<button type="button" on:click={retryQuestion}>重做本题</button>
					</div>
				{/if}

				<div class="analysis-panel" class:open={showAnalysis || resolvedSubmitted}>
					<button type="button" on:click={() => (showAnalysis = !showAnalysis)}>
						<Icon icon="material-symbols:school-outline-rounded" class="button-icon" />
						{showAnalysis || resolvedSubmitted ? "解析已展开" : "查看解析"}
					</button>

					{#if showAnalysis || resolvedSubmitted}
						<div class="analysis-grid">
							{#if showTranslation}
								<div>
									<span>题干翻译</span>
									<p>{currentQuestion.stemTranslation}</p>
								</div>
								<div>
									<span>选项翻译</span>
									<p>{currentQuestion.optionTranslation}</p>
								</div>
							{/if}
							<div>
								<span>重点词汇</span>
								<p>{currentQuestion.keyVocabulary}</p>
							</div>
						</div>
					{/if}
				</div>
			</article>
		{:else}
			<section class="empty-card">
				<Icon icon="material-symbols:quiz-outline-rounded" class="empty-icon" />
				<h2>这个范围暂时没有题目</h2>
				<p>可以切回全部题目，或者先刷一遍后再进入错题模式。</p>
				<button type="button" on:click={() => changeMode("all")}>回到全部</button>
			</section>
		{/if}
	</div>
</section>

<style>
	.quiz-shell {
		--quiz-accent: var(--accent);
		--quiz-accent-strong: var(--olive);
		--quiz-text: var(--ink);
		--quiz-soft: var(--ink);
		--quiz-muted: var(--muted);
		position: relative;
		width: 100%;
		min-height: calc(100vh - 7.5rem);
		padding: 1rem;
		border-radius: 4px;
		background: color-mix(in srgb, var(--accent) 10%, var(--surface)) !important;
	}

	.quiz-hero {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1rem;
		padding: 0.15rem 0.1rem 1rem;
	}

	.eyebrow {
		color: var(--quiz-accent);
		font-size: 0.76rem;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
	}

	h1 {
		margin: 0.25rem 0 0.55rem;
		color: var(--ink);
		font-size: clamp(1.85rem, 4vw, 2.65rem);
		font-weight: 600;
		letter-spacing: 0;
		line-height: 1.1;
	}

	.quiz-hero p {
		max-width: 45rem;
		color: var(--ink);
		line-height: 1.72;
	}

	.hero-stats,
	.mini-stats {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 0.7rem;
	}

	.hero-stats > div,
	.mini-stats > div,
	.progress-card {
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--surface);
		padding: 0.85rem;
	}

	.hero-stats strong,
	.mini-stats strong {
		display: block;
		color: var(--ink);
		font-size: 1.45rem;
		line-height: 1;
	}

	.hero-stats span,
	.mini-stats span {
		margin-top: 0.35rem;
		display: block;
		color: var(--muted);
		font-size: 0.78rem;
		font-weight: 600;
	}

	.control-panel {
		display: grid;
		gap: 0.8rem;
		margin-bottom: 0.9rem;
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--surface);
		padding: 0.75rem;
	}

	.unit-tabs,
	.mode-tabs,
	.tool-grid {
		display: flex;
		flex-wrap: wrap;
		gap: 0.55rem;
	}

	button {
		border: 0;
		cursor: pointer;
		font: inherit;
		letter-spacing: 0;
	}

	.unit-tabs button,
	.mode-tabs button,
	.tool-grid button,
	.danger-btn,
	.nav-btn,
	.submit-btn,
	.analysis-panel > button,
	.empty-card button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.45rem;
		min-height: 2.55rem;
		border-radius: 4px;
		background: var(--soft);
		color: var(--quiz-soft);
		font-weight: 600;
		transition:
			background-color 160ms ease,
			color 160ms ease,
			transform 160ms ease,
			border-color 160ms ease;
	}

	.unit-tabs button,
	.mode-tabs button {
		padding: 0 0.9rem;
		border: 1px solid var(--line);
	}

	.button-icon {
		font-size: 1.1rem;
	}

	.unit-tabs button:hover,
	.mode-tabs button:hover,
	.tool-grid button:hover,
	.nav-btn:hover,
	.analysis-panel > button:hover,
	.empty-card button:hover {
		color: var(--quiz-accent);
		background: var(--soft);
	}

	.unit-tabs button.active,
	.mode-tabs button.active,
	.submit-btn {
		border-color: var(--accent);
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--quiz-text);
		text-shadow: none;
		box-shadow: none;
	}

	.quiz-layout {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1rem;
	}

	.side-panel,
	.question-card,
	.empty-card {
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--surface);
		box-shadow: none;
	}

	.side-panel {
		display: flex;
		flex-direction: column;
		gap: 0.85rem;
		padding: 1rem;
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
		font-size: 0.82rem;
		font-weight: 600;
	}

	.progress-title strong {
		color: var(--quiz-text);
		font-size: 1.35rem;
		text-shadow: none;
	}

	.progress-track {
		overflow: hidden;
		height: 0.5rem;
		margin: 0.8rem 0;
		border-radius: 999px;
		background: var(--soft);
	}

	.progress-track > div {
		height: 100%;
		border-radius: inherit;
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		transition: width 220ms ease;
	}

	.mini-stats {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.tool-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.tool-grid button,
	.danger-btn {
		padding: 0 0.65rem;
	}

	.tool-grid button.active-tool {
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--quiz-text);
		text-shadow: none;
		box-shadow: none;
	}

	.danger-btn {
		color: var(--quiz-danger);
		background: color-mix(in srgb, var(--quiz-danger) 10%, var(--surface));
	}

	.question-list-card {
		display: grid;
		gap: 0.75rem;
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--surface);
		padding: 0.85rem;
	}

	.question-list-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		color: var(--quiz-text);
	}

	.question-list-head strong {
		font-size: 0.95rem;
	}

	.question-list-head span {
		color: var(--quiz-muted);
		font-size: 0.78rem;
		font-weight: 600;
	}

	.question-list {
		display: grid;
		gap: 0.45rem;
		max-height: 22rem;
		overflow-y: auto;
		padding-right: 0.25rem;
	}

	.question-list button {
		display: grid;
		grid-template-columns: 2rem minmax(0, 1fr) auto;
		align-items: center;
		gap: 0.55rem;
		min-height: 2.45rem;
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--soft);
		padding: 0.35rem 0.5rem;
		color: var(--quiz-soft);
		text-align: left;
	}

	.question-list button:hover,
	.question-list button.current {
		border-color: var(--accent);
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--quiz-text);
	}

	.question-list button.answered:not(.current) {
		border-color: var(--quiz-success);
	}

	.question-list button.wrong:not(.current) {
		border-color: var(--quiz-danger);
		background: color-mix(in srgb, var(--quiz-danger) 10%, var(--surface));
	}

	.question-list button span {
		display: grid;
		place-items: center;
		width: 2rem;
		height: 1.85rem;
		border-radius: 4px;
		background: var(--soft);
		color: var(--quiz-text);
		font-size: 0.78rem;
		font-weight: 600;
	}

	.question-list button.current span {
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		box-shadow: none;
	}

	.question-list button strong {
		overflow: hidden;
		color: inherit;
		font-size: 0.82rem;
		font-weight: 600;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.list-star {
		color: var(--quiz-favorite);
		font-size: 1rem;
	}

	.question-card {
		padding: 1rem;
		min-height: 32rem;
	}

	.question-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.question-head span {
		display: inline-flex;
		margin-bottom: 0.35rem;
		color: var(--quiz-accent);
		font-size: 0.8rem;
		font-weight: 600;
	}

	.question-head strong {
		display: block;
		color: var(--ink);
		font-size: 1.2rem;
	}

	.star-btn {
		display: grid;
		place-items: center;
		width: 2.65rem;
		height: 2.65rem;
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--soft);
		color: var(--muted);
	}

	.star-btn.active {
		color: var(--quiz-favorite);
		background: color-mix(in srgb, var(--quiz-favorite) 10%, var(--surface));
	}

	.star-icon {
		font-size: 1.35rem;
	}

	.question-text {
		margin: 0 0 1.2rem;
		color: var(--ink);
		font-size: clamp(1.06rem, 1.8vw, 1.22rem);
		font-weight: 600;
		line-height: 1.82;
	}

	.options {
		display: grid;
		gap: 0.7rem;
	}

	.option {
		display: grid;
		grid-template-columns: 2.2rem minmax(0, 1fr);
		align-items: center;
		gap: 0.85rem;
		width: 100%;
		min-height: 3.65rem;
		border: 1px solid var(--line);
		border-radius: 4px;
		background: var(--surface);
		padding: 0.75rem;
		color: var(--ink);
		text-align: left;
	}

	.option span {
		display: grid;
		place-items: center;
		width: 2.2rem;
		height: 2.2rem;
		border-radius: 4px;
		background: var(--soft);
		color: var(--quiz-text);
		font-weight: 600;
	}

	.option strong {
		font-size: 1rem;
		font-weight: 600;
		line-height: 1.45;
		word-break: break-word;
	}

	.option:hover,
	.option-selected {
		border-color: var(--accent);
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--quiz-text);
		box-shadow: none;
	}

	.option-selected span {
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--quiz-text);
		box-shadow: none;
	}

	.selection-banner {
		display: flex;
		align-items: center;
		gap: 0.8rem;
		margin-top: 1rem;
		border: 1px solid var(--accent);
		border-radius: 4px;
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		padding: 0.85rem 0.95rem;
		color: var(--quiz-text);
		box-shadow: none;
	}

	.selection-icon {
		flex: 0 0 auto;
		color: var(--quiz-accent);
		font-size: 1.55rem;
	}

	.selection-banner strong,
	.selection-banner span {
		display: block;
	}

	.selection-banner strong {
		color: var(--quiz-text);
		font-size: 0.95rem;
	}

	.selection-banner span {
		margin-top: 0.18rem;
		color: var(--quiz-muted);
		font-size: 0.86rem;
		line-height: 1.45;
	}

	.option-correct {
		border-color: var(--quiz-success);
		background: color-mix(in srgb, var(--quiz-success) 10%, var(--surface));
	}

	.option-wrong {
		border-color: var(--quiz-danger);
		background: color-mix(in srgb, var(--quiz-danger) 10%, var(--surface));
	}

	.option-muted {
		opacity: 0.58;
	}

	.answer-actions {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.7rem;
		margin-top: 1rem;
	}

	.nav-btn,
	.submit-btn {
		padding: 0 1rem;
	}

	button:disabled {
		cursor: not-allowed;
		opacity: 0.58;
		color: var(--muted);
		text-shadow: none;
	}

	.result-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 0.8rem;
		margin-top: 1rem;
		border-radius: 4px;
		padding: 0.9rem;
	}

	.result-banner > div {
		flex: 1 1 14rem;
	}

	.result-banner button {
		min-height: 2.25rem;
		border-radius: 4px;
		background: var(--soft);
		color: var(--ink);
		padding: 0 0.8rem;
		font-weight: 600;
	}

	.result-icon {
		font-size: 1.8rem;
	}

	.result-banner strong,
	.result-banner span {
		display: block;
	}

	.result-banner strong {
		color: var(--ink);
	}

	.result-banner span {
		color: var(--muted);
		font-size: 0.88rem;
	}

	.result-correct {
		background: color-mix(in srgb, var(--quiz-success) 10%, var(--surface));
		color: var(--quiz-success);
	}

	.result-wrong {
		background: color-mix(in srgb, var(--quiz-danger) 10%, var(--surface));
		color: var(--quiz-danger);
	}

	.analysis-panel {
		margin-top: 1rem;
		border-radius: 4px;
		background: var(--surface);
		padding: 0.75rem;
	}

	.analysis-panel > button {
		width: 100%;
		background: var(--soft);
	}

	.analysis-grid {
		display: grid;
		gap: 0.75rem;
		margin-top: 0.75rem;
	}

	.analysis-grid > div {
		border-left: 3px solid var(--accent);
		border-radius: 4px;
		background: var(--surface);
		padding: 0.85rem 0.9rem;
	}

	.analysis-grid span {
		color: var(--quiz-accent);
		font-size: 0.78rem;
		font-weight: 600;
	}

	.analysis-grid p {
		margin: 0.35rem 0 0;
		color: var(--ink);
		line-height: 1.7;
	}

	.empty-card {
		display: grid;
		place-items: center;
		min-height: 26rem;
		padding: 2rem;
		text-align: center;
	}

	.empty-icon {
		color: var(--quiz-accent);
		font-size: 3rem;
	}

	.empty-card h2 {
		margin: 0.8rem 0 0.4rem;
		color: var(--ink);
	}

	.empty-card p {
		color: var(--muted);
	}

	.empty-card button {
		margin-top: 1rem;
		padding: 0 1.2rem;
	}

	@media (min-width: 768px) {
		.quiz-shell {
			padding: 1.35rem;
		}

		.quiz-hero {
			grid-template-columns: minmax(0, 1fr) 18rem;
			align-items: end;
		}

		.answer-actions {
			grid-template-columns: 1fr 1.3fr 1fr;
		}
	}

	@media (min-width: 1024px) {
		.quiz-layout {
			grid-template-columns: 17rem minmax(0, 1fr);
			align-items: start;
		}

		.side-panel {
			position: sticky;
			top: 6rem;
		}

		.question-card {
			padding: 1.5rem;
		}
	}

	/* Paper, ink, and clear answer states follow the rest of the journal. */
	.quiz-shell {
		background: transparent !important;
		border: 0;
		border-radius: 0;
		box-shadow: none;
		color: var(--ink);
		padding: 0;
	}
	h1 { font-weight: 500; letter-spacing: -.045em; line-height: 1.35; }
	.eyebrow { font-family: var(--font-mono); font-size: 10px; color: var(--muted); font-weight: 400; letter-spacing: .13em; }
	.submit-btn { background: var(--accent); border-color: var(--accent); color: var(--paper); box-shadow: none; text-shadow: none; }
	.submit-btn:hover { background: var(--ink); border-color: var(--ink); color: var(--paper); }
	.option-selected {
		border-color: var(--accent);
		background: color-mix(in srgb, var(--accent) 10%, var(--surface));
		color: var(--ink);
		box-shadow: inset 3px 0 0 var(--accent);
	}
	.option-correct {
		background: color-mix(in srgb, var(--quiz-success) 10%, var(--surface));
		border-color: var(--quiz-success);
		box-shadow: inset 3px 0 0 var(--quiz-success);
	}
	.option-wrong {
		background: color-mix(in srgb, var(--quiz-danger) 10%, var(--surface));
		border-color: var(--quiz-danger);
		box-shadow: inset 3px 0 0 var(--quiz-danger);
	}
	button:disabled { color: var(--muted) !important; }
</style>
