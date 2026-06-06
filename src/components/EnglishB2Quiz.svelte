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
		--quiz-accent: #67e8f9;
		--quiz-accent-strong: #a7f3d0;
		--quiz-text: #f8fafc;
		--quiz-soft: rgba(226, 232, 240, 0.9);
		--quiz-muted: rgba(203, 213, 225, 0.78);
		position: relative;
		width: 100%;
		min-height: calc(100vh - 7.5rem);
		padding: 1rem;
		border-radius: 1.25rem;
		background:
			radial-gradient(circle at 8% 0%, rgba(45, 212, 191, 0.12), transparent 23rem),
			linear-gradient(135deg, rgba(15, 23, 42, 0.82), rgba(2, 6, 23, 0.68)),
			rgba(15, 23, 42, 0.72) !important;
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
		font-weight: 800;
		letter-spacing: 0.08em;
		text-transform: uppercase;
	}

	h1 {
		margin: 0.25rem 0 0.55rem;
		color: rgba(248, 250, 252, 0.96);
		font-size: clamp(1.85rem, 4vw, 2.65rem);
		font-weight: 950;
		letter-spacing: 0;
		line-height: 1.1;
	}

	.quiz-hero p {
		max-width: 45rem;
		color: rgba(203, 213, 225, 0.86);
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
		border: 1px solid rgba(226, 232, 240, 0.12);
		border-radius: 1rem;
		background: rgba(15, 23, 42, 0.42);
		padding: 0.85rem;
	}

	.hero-stats strong,
	.mini-stats strong {
		display: block;
		color: #f8fafc;
		font-size: 1.45rem;
		line-height: 1;
	}

	.hero-stats span,
	.mini-stats span {
		margin-top: 0.35rem;
		display: block;
		color: rgba(203, 213, 225, 0.72);
		font-size: 0.78rem;
		font-weight: 700;
	}

	.control-panel {
		display: grid;
		gap: 0.8rem;
		margin-bottom: 0.9rem;
		border: 1px solid rgba(226, 232, 240, 0.1);
		border-radius: 1rem;
		background: rgba(2, 6, 23, 0.22);
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
		border-radius: 0.75rem;
		background: rgba(148, 163, 184, 0.11);
		color: var(--quiz-soft);
		font-weight: 800;
		transition:
			background-color 160ms ease,
			color 160ms ease,
			transform 160ms ease,
			border-color 160ms ease;
	}

	.unit-tabs button,
	.mode-tabs button {
		padding: 0 0.9rem;
		border: 1px solid rgba(226, 232, 240, 0.1);
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
		background: rgba(148, 163, 184, 0.17);
	}

	.unit-tabs button.active,
	.mode-tabs button.active,
	.submit-btn {
		border-color: rgba(103, 232, 249, 0.55);
		background:
			linear-gradient(135deg, rgba(34, 211, 238, 0.3), rgba(45, 212, 191, 0.18)),
			rgba(15, 23, 42, 0.66);
		color: var(--quiz-text);
		text-shadow: 0 0 14px rgba(103, 232, 249, 0.38);
		box-shadow:
			inset 0 0 0 1px rgba(167, 243, 208, 0.2),
			0 0 24px rgba(34, 211, 238, 0.14);
	}

	.quiz-layout {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1rem;
	}

	.side-panel,
	.question-card,
	.empty-card {
		border: 1px solid rgba(226, 232, 240, 0.12);
		border-radius: 1.2rem;
		background:
			linear-gradient(135deg, rgba(15, 23, 42, 0.58), rgba(2, 6, 23, 0.42)),
			rgba(15, 23, 42, 0.46);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
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
		color: rgba(203, 213, 225, 0.76);
		font-size: 0.82rem;
		font-weight: 800;
	}

	.progress-title strong {
		color: var(--quiz-text);
		font-size: 1.35rem;
		text-shadow: 0 0 16px rgba(103, 232, 249, 0.24);
	}

	.progress-track {
		overflow: hidden;
		height: 0.5rem;
		margin: 0.8rem 0;
		border-radius: 999px;
		background: rgba(148, 163, 184, 0.16);
	}

	.progress-track > div {
		height: 100%;
		border-radius: inherit;
		background: linear-gradient(90deg, #22d3ee, var(--quiz-accent-strong));
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
		background:
			linear-gradient(135deg, rgba(34, 211, 238, 0.28), rgba(45, 212, 191, 0.2)),
			rgba(15, 23, 42, 0.62);
		color: var(--quiz-text);
		text-shadow: 0 0 14px rgba(103, 232, 249, 0.42);
		box-shadow:
			inset 0 0 0 1px rgba(103, 232, 249, 0.44),
			0 0 24px rgba(34, 211, 238, 0.14);
	}

	.danger-btn {
		color: rgba(254, 202, 202, 0.88);
		background: rgba(127, 29, 29, 0.24);
	}

	.question-list-card {
		display: grid;
		gap: 0.75rem;
		border: 1px solid rgba(226, 232, 240, 0.12);
		border-radius: 1rem;
		background: rgba(2, 6, 23, 0.24);
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
		font-weight: 800;
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
		border: 1px solid rgba(226, 232, 240, 0.1);
		border-radius: 0.75rem;
		background: rgba(148, 163, 184, 0.08);
		padding: 0.35rem 0.5rem;
		color: var(--quiz-soft);
		text-align: left;
	}

	.question-list button:hover,
	.question-list button.current {
		border-color: rgba(103, 232, 249, 0.56);
		background:
			linear-gradient(135deg, rgba(34, 211, 238, 0.18), rgba(45, 212, 191, 0.1)),
			rgba(15, 23, 42, 0.62);
		color: var(--quiz-text);
	}

	.question-list button.answered:not(.current) {
		border-color: rgba(74, 222, 128, 0.24);
	}

	.question-list button.wrong:not(.current) {
		border-color: rgba(248, 113, 113, 0.42);
		background: rgba(127, 29, 29, 0.18);
	}

	.question-list button span {
		display: grid;
		place-items: center;
		width: 2rem;
		height: 1.85rem;
		border-radius: 0.55rem;
		background: rgba(148, 163, 184, 0.14);
		color: var(--quiz-text);
		font-size: 0.78rem;
		font-weight: 950;
	}

	.question-list button.current span {
		background: rgba(103, 232, 249, 0.24);
		box-shadow: 0 0 16px rgba(103, 232, 249, 0.16);
	}

	.question-list button strong {
		overflow: hidden;
		color: inherit;
		font-size: 0.82rem;
		font-weight: 850;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.list-star {
		color: #facc15;
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
		font-weight: 900;
	}

	.question-head strong {
		display: block;
		color: #f8fafc;
		font-size: 1.2rem;
	}

	.star-btn {
		display: grid;
		place-items: center;
		width: 2.65rem;
		height: 2.65rem;
		border: 1px solid rgba(226, 232, 240, 0.12);
		border-radius: 0.8rem;
		background: rgba(148, 163, 184, 0.11);
		color: rgba(226, 232, 240, 0.78);
	}

	.star-btn.active {
		color: #facc15;
		background: rgba(250, 204, 21, 0.14);
	}

	.star-icon {
		font-size: 1.35rem;
	}

	.question-text {
		margin: 0 0 1.2rem;
		color: #eef4fb;
		font-size: clamp(1.06rem, 1.8vw, 1.22rem);
		font-weight: 760;
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
		border: 1px solid rgba(226, 232, 240, 0.1);
		border-radius: 0.95rem;
		background: rgba(15, 23, 42, 0.38);
		padding: 0.75rem;
		color: rgba(226, 232, 240, 0.88);
		text-align: left;
	}

	.option span {
		display: grid;
		place-items: center;
		width: 2.2rem;
		height: 2.2rem;
		border-radius: 0.7rem;
		background: rgba(148, 163, 184, 0.15);
		color: var(--quiz-text);
		font-weight: 950;
	}

	.option strong {
		font-size: 1rem;
		font-weight: 780;
		line-height: 1.45;
		word-break: break-word;
	}

	.option:hover,
	.option-selected {
		border-color: rgba(103, 232, 249, 0.62);
		background:
			linear-gradient(135deg, rgba(34, 211, 238, 0.16), rgba(45, 212, 191, 0.1)),
			rgba(148, 163, 184, 0.14);
		color: var(--quiz-text);
		box-shadow: inset 0 0 0 1px rgba(103, 232, 249, 0.16);
	}

	.option-selected span {
		background: rgba(103, 232, 249, 0.22);
		color: var(--quiz-text);
		box-shadow: 0 0 18px rgba(103, 232, 249, 0.2);
	}

	.selection-banner {
		display: flex;
		align-items: center;
		gap: 0.8rem;
		margin-top: 1rem;
		border: 1px solid rgba(103, 232, 249, 0.28);
		border-radius: 1rem;
		background:
			linear-gradient(135deg, rgba(34, 211, 238, 0.18), rgba(45, 212, 191, 0.1)),
			rgba(15, 23, 42, 0.42);
		padding: 0.85rem 0.95rem;
		color: var(--quiz-text);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
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
		border-color: rgba(74, 222, 128, 0.75);
		background: rgba(22, 101, 52, 0.3);
	}

	.option-wrong {
		border-color: rgba(248, 113, 113, 0.78);
		background: rgba(127, 29, 29, 0.3);
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
		color: rgba(226, 232, 240, 0.66) !important;
		text-shadow: none;
	}

	.result-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 0.8rem;
		margin-top: 1rem;
		border-radius: 1rem;
		padding: 0.9rem;
	}

	.result-banner > div {
		flex: 1 1 14rem;
	}

	.result-banner button {
		min-height: 2.25rem;
		border-radius: 0.7rem;
		background: rgba(255, 255, 255, 0.1);
		color: rgba(248, 250, 252, 0.86);
		padding: 0 0.8rem;
		font-weight: 850;
	}

	.result-icon {
		font-size: 1.8rem;
	}

	.result-banner strong,
	.result-banner span {
		display: block;
	}

	.result-banner strong {
		color: #f8fafc;
	}

	.result-banner span {
		color: rgba(226, 232, 240, 0.76);
		font-size: 0.88rem;
	}

	.result-correct {
		background: rgba(22, 101, 52, 0.28);
		color: #86efac;
	}

	.result-wrong {
		background: rgba(127, 29, 29, 0.28);
		color: #fca5a5;
	}

	.analysis-panel {
		margin-top: 1rem;
		border-radius: 1rem;
		background: rgba(2, 6, 23, 0.28);
		padding: 0.75rem;
	}

	.analysis-panel > button {
		width: 100%;
		background: rgba(148, 163, 184, 0.1);
	}

	.analysis-grid {
		display: grid;
		gap: 0.75rem;
		margin-top: 0.75rem;
	}

	.analysis-grid > div {
		border-left: 3px solid rgba(103, 232, 249, 0.68);
		border-radius: 0.8rem;
		background: rgba(15, 23, 42, 0.34);
		padding: 0.85rem 0.9rem;
	}

	.analysis-grid span {
		color: var(--quiz-accent);
		font-size: 0.78rem;
		font-weight: 950;
	}

	.analysis-grid p {
		margin: 0.35rem 0 0;
		color: rgba(226, 232, 240, 0.88);
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
		color: #f8fafc;
	}

	.empty-card p {
		color: rgba(203, 213, 225, 0.78);
	}

	.empty-card button {
		margin-top: 1rem;
		padding: 0 1.2rem;
	}

	:global(:root:not(.dark)) .quiz-shell {
		color: var(--quiz-text);
	}

	:global(:root:not(.dark)) h1,
	:global(:root:not(.dark)) .hero-stats strong,
	:global(:root:not(.dark)) .question-head strong,
	:global(:root:not(.dark)) .question-text,
	:global(:root:not(.dark)) .empty-card h2 {
		color: var(--quiz-text);
	}

	:global(:root:not(.dark)) .quiz-hero p,
	:global(:root:not(.dark)) .hero-stats span,
	:global(:root:not(.dark)) .mini-stats span,
	:global(:root:not(.dark)) .progress-title span,
	:global(:root:not(.dark)) .progress-meta,
	:global(:root:not(.dark)) .empty-card p {
		color: var(--quiz-muted);
	}

	:global(:root:not(.dark)) .hero-stats > div,
	:global(:root:not(.dark)) .mini-stats > div,
	:global(:root:not(.dark)) .progress-card,
	:global(:root:not(.dark)) .side-panel,
	:global(:root:not(.dark)) .question-card,
	:global(:root:not(.dark)) .empty-card {
		background: rgba(15, 23, 42, 0.5);
		border-color: rgba(226, 232, 240, 0.12);
	}

	:global(:root:not(.dark)) .option,
	:global(:root:not(.dark)) .analysis-grid > div,
	:global(:root:not(.dark)) .analysis-panel {
		background: rgba(15, 23, 42, 0.42);
		border-color: rgba(226, 232, 240, 0.12);
		color: var(--quiz-soft);
	}

	:global(:root:not(.dark)) .analysis-grid p {
		color: var(--quiz-soft);
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
</style>
