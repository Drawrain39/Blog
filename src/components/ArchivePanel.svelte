<script lang="ts">
import { onMount } from "svelte";
import type { PostForList } from "../utils/content-utils";

import I18nKey from "../i18n/i18nKey";
import { i18n } from "../i18n/translation";
import { getPostUrlBySlug } from "../utils/url-utils";

export let tags: string[] = [];
export let categories: string[] = [];
export let sortedPosts: PostForList[] = [];

const quickFilters = [
	{ key: "all", label: "全部", description: "查看全部文章" },
	{ key: "ctf", label: "CTF", description: "筛选 CTF 题解", category: "CTF" },
	{ key: "cpp", label: "C++", description: "筛选 C++ 与数据结构", category: "C++" },
	{ key: "ai", label: "AI", description: "筛选 AI 与 Agent 文章", category: "AI" },
	{ key: "notes", label: "Notes", description: "筛选笔记类文章", tag: "notes" },
	{ key: "math", label: "Math", description: "筛选数学文章", category: "Math" },
] as const;

type FilterKey = (typeof quickFilters)[number]["key"];

interface Group {
	year: number;
	posts: PostForList[];
}

interface StatItem {
	label: string;
	value: string;
}

let activeFilter: FilterKey = "all";
let queryTags: string[] = [];
let queryCategories: string[] = [];
let showUncategorized = false;

let filteredPosts: PostForList[] = [];
let groups: Group[] = [];
let stats: StatItem[] = [];
let activeFilterName = "全部";
let hasActiveQueryFilter = false;

$: hasActiveQueryFilter =
	queryTags.length > 0 || queryCategories.length > 0 || showUncategorized;
$: filteredPosts = filterPosts(
	sortedPosts,
	activeFilter,
	queryTags,
	queryCategories,
	showUncategorized,
);
$: groups = groupPosts(filteredPosts);
$: activeFilterName = getActiveFilterName(
	activeFilter,
	queryTags,
	queryCategories,
	showUncategorized,
);
$: stats = [
	{ label: "总文章", value: `${formatNumber(sortedPosts.length)} 篇` },
	{ label: "总字数", value: formatWords(sumWords(sortedPosts)) },
	{ label: "最近更新", value: getLatestDate(sortedPosts) },
	{ label: "当前结果", value: `${formatNumber(filteredPosts.length)} 篇` },
];

function cleanList(values: string[]) {
	return values.map((value) => value.trim()).filter(Boolean);
}

function normalize(value: string | null | undefined) {
	return (value ?? "").trim().toLowerCase();
}

function getQuickFilter(key: FilterKey) {
	return quickFilters.find((filter) => filter.key === key);
}

function inferActiveFilter(tagList: string[], categoryList: string[]) {
	const matched = quickFilters.find((filter) => {
		if ("category" in filter && filter.category) {
			return categoryList.some(
				(category) => normalize(category) === normalize(filter.category),
			);
		}
		if ("tag" in filter && filter.tag) {
			return tagList.some((tag) => normalize(tag) === normalize(filter.tag));
		}
		return false;
	});

	return matched?.key ?? "all";
}

function isQuickFilterActive(
	key: FilterKey,
	selectedFilter: FilterKey,
	hasQueryFilter: boolean,
) {
	if (key === "all") return selectedFilter === "all" && !hasQueryFilter;
	return selectedFilter === key;
}

function postMatchesCategory(post: PostForList, category: string) {
	return normalize(post.data.category) === normalize(category);
}

function postMatchesTag(post: PostForList, tag: string) {
	return (
		Array.isArray(post.data.tags) &&
		post.data.tags.some((postTag) => normalize(postTag) === normalize(tag))
	);
}

function filterPosts(
	posts: PostForList[],
	selectedFilter: FilterKey,
	tagList: string[],
	categoryList: string[],
	uncategorized: boolean,
) {
	let nextPosts = posts;

	if (tagList.length > 0) {
		nextPosts = nextPosts.filter((post) =>
			tagList.some((tag) => postMatchesTag(post, tag)),
		);
	}

	if (categoryList.length > 0) {
		nextPosts = nextPosts.filter((post) =>
			categoryList.some((category) => postMatchesCategory(post, category)),
		);
	}

	if (uncategorized) {
		nextPosts = nextPosts.filter((post) => !post.data.category);
	}

	const quickFilter = getQuickFilter(selectedFilter);
	if (quickFilter && "category" in quickFilter && quickFilter.category) {
		nextPosts = nextPosts.filter((post) =>
			postMatchesCategory(post, quickFilter.category),
		);
	}
	if (quickFilter && "tag" in quickFilter && quickFilter.tag) {
		nextPosts = nextPosts.filter((post) =>
			postMatchesTag(post, quickFilter.tag),
		);
	}

	return nextPosts;
}

function groupPosts(posts: PostForList[]) {
	const grouped = posts.reduce(
		(acc, post) => {
			const year = toDate(post.data.published).getFullYear();
			if (!acc[year]) acc[year] = [];
			acc[year].push(post);
			return acc;
		},
		{} as Record<number, PostForList[]>,
	);

	return Object.keys(grouped)
		.map((yearStr) => {
			const year = Number.parseInt(yearStr, 10);
			return {
				year,
				posts: grouped[year].sort(
					(a, b) =>
						toDate(b.data.published).getTime() -
						toDate(a.data.published).getTime(),
				),
			};
		})
		.sort((a, b) => b.year - a.year);
}

function toDate(date: Date | string | number) {
	if (date instanceof Date) return date;
	return new Date(date);
}

function formatDate(date: Date | string | number) {
	const normalizedDate = toDate(date);
	const month = (normalizedDate.getMonth() + 1).toString().padStart(2, "0");
	const day = normalizedDate.getDate().toString().padStart(2, "0");
	return `${month}-${day}`;
}

function formatFullDate(date: Date | string | number) {
	const normalizedDate = toDate(date);
	const month = (normalizedDate.getMonth() + 1).toString().padStart(2, "0");
	const day = normalizedDate.getDate().toString().padStart(2, "0");
	return `${normalizedDate.getFullYear()}-${month}-${day}`;
}

function formatNumber(value: number) {
	return new Intl.NumberFormat("zh-CN").format(value);
}

function formatWords(value: number) {
	const count = Math.round(value);
	if (count >= 10000) {
		return `${(count / 10000).toFixed(1).replace(/\.0$/, "")} 万字`;
	}
	return `${formatNumber(count)} 字`;
}

function formatTag(tagList: string[]) {
	return tagList.map((tag) => `#${tag}`).join(" ");
}

function sumWords(posts: PostForList[]) {
	return posts.reduce((sum, post) => sum + (post.wordCount ?? 0), 0);
}

function getLatestDate(posts: PostForList[]) {
	let latestTime = 0;

	for (const post of posts) {
		const candidate = toDate(post.data.updated ?? post.data.published).getTime();
		if (candidate > latestTime) latestTime = candidate;
	}

	return latestTime > 0 ? formatFullDate(latestTime) : "-";
}

function getActiveFilterName(
	selectedFilter: FilterKey,
	tagList: string[],
	categoryList: string[],
	uncategorized: boolean,
) {
	if (selectedFilter !== "all") {
		return getQuickFilter(selectedFilter)?.label ?? "全部";
	}

	const labels = [
		...categoryList.map((category) => `分类：${category}`),
		...tagList.map((tag) => `#${tag}`),
	];

	if (uncategorized) labels.push("未分类");
	return labels.length > 0 ? labels.join(" / ") : "全部";
}

function setQuickFilter(key: FilterKey) {
	activeFilter = key;
	queryTags = [];
	queryCategories = [];
	showUncategorized = false;
	updateArchiveUrl(key);
}

function clearFilters() {
	setQuickFilter("all");
}

function updateArchiveUrl(key: FilterKey) {
	if (typeof window === "undefined") return;

	const url = new URL(window.location.href);
	url.search = "";

	const filter = getQuickFilter(key);
	if (filter && "category" in filter && filter.category) {
		url.searchParams.set("category", filter.category);
	}
	if (filter && "tag" in filter && filter.tag) {
		url.searchParams.set("tag", filter.tag);
	}

	window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
}

onMount(() => {
	const params = new URLSearchParams(window.location.search);

	queryTags = params.has("tag") ? cleanList(params.getAll("tag")) : cleanList(tags);
	queryCategories = params.has("category")
		? cleanList(params.getAll("category"))
		: cleanList(categories);
	showUncategorized = params.has("uncategorized");
	activeFilter = inferActiveFilter(queryTags, queryCategories);
});
</script>

<div class="card-base archive-shell px-5 py-5 md:px-8 md:py-6">
	<div class="archive-head">
		<div class="min-w-0">
			<div class="text-xs font-bold uppercase text-[var(--primary)]">Archive</div>
			<div class="mt-1 flex min-w-0 flex-wrap items-center gap-2">
				<h1 class="text-2xl font-black text-90">文章归档</h1>
				<span class="active-filter-label">{activeFilterName}</span>
			</div>
			<p class="mt-2 text-sm text-50">
				共 {formatNumber(sortedPosts.length)} 篇，当前 {formatNumber(filteredPosts.length)} 篇
			</p>
		</div>

		<div class="stat-strip" aria-label="归档统计">
			{#each stats as stat}
				<div class="stat-pill">
					<span>{stat.label}</span>
					<strong>{stat.value}</strong>
				</div>
			{/each}
		</div>
	</div>

	<div class="filter-row" aria-label="快速筛选">
		{#each quickFilters as filter}
			<button
				type="button"
				class="filter-btn"
				class:filter-btn-active={isQuickFilterActive(filter.key, activeFilter, hasActiveQueryFilter)}
				aria-pressed={isQuickFilterActive(filter.key, activeFilter, hasActiveQueryFilter)}
				title={filter.description}
				on:click={() => setQuickFilter(filter.key)}
			>
				{filter.label}
			</button>
		{/each}
	</div>

	{#if hasActiveQueryFilter && activeFilter === "all"}
		<div class="query-strip">
			<span class="truncate">{activeFilterName}</span>
			<button type="button" on:click={clearFilters}>清除</button>
		</div>
	{/if}

	{#if groups.length === 0}
		<div class="empty-state">
			<div class="text-lg font-black text-75">当前筛选没有文章</div>
			<div class="mt-1 text-sm text-50">换一个方向看看。</div>
		</div>
	{:else}
		<div class="archive-timeline">
			{#each groups as group}
				<div>
					<div class="flex h-[3.75rem] w-full flex-row items-center">
						<div class="w-[15%] text-right text-2xl font-bold text-75 transition md:w-[10%]">
							{group.year}
						</div>
						<div class="w-[15%] md:w-[10%]">
							<div
								class="z-50 mx-auto h-3 w-3 rounded-full bg-none outline outline-3 -outline-offset-[2px] outline-[var(--primary)]"
							></div>
						</div>
						<div class="w-[70%] text-left text-50 transition md:w-[80%]">
							{group.posts.length} {i18n(group.posts.length === 1 ? I18nKey.postCount : I18nKey.postsCount)}
						</div>
					</div>

					{#each group.posts as post}
						<a
							href={getPostUrlBySlug(post.slug)}
							aria-label={post.data.title}
							class="group btn-plain !block h-10 w-full rounded-lg hover:text-[initial]"
						>
							<div class="flex h-full flex-row items-center justify-start">
								<div class="w-[15%] text-right text-sm text-50 transition md:w-[10%]">
									{formatDate(post.data.published)}
								</div>

								<div class="dash-line relative flex h-full w-[15%] items-center md:w-[10%]">
									<div
										class="z-50 mx-auto h-1 w-1 rounded bg-[oklch(0.5_0.05_var(--hue))] outline outline-4 outline-[var(--card-bg)] transition-all group-hover:h-5 group-hover:bg-[var(--primary)] group-hover:outline-[var(--btn-plain-bg-hover)] group-active:outline-[var(--btn-plain-bg-active)]"
									></div>
								</div>

								<div
									class="w-[70%] overflow-hidden overflow-ellipsis whitespace-nowrap pr-8 text-left font-bold text-75 transition-all group-hover:translate-x-1 group-hover:text-[var(--primary)] md:w-[55%] md:max-w-[55%]"
								>
									{post.data.title}
								</div>

								<div class="hidden min-w-0 items-center gap-2 text-left text-xs text-30 transition md:flex md:w-[25%]">
									{#if post.data.category}
										<span class="category-chip">{post.data.category}</span>
									{/if}
									<span class="truncate">{formatTag(post.data.tags)}</span>
								</div>
							</div>
						</a>
					{/each}
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.archive-shell {
		border: 1px solid rgba(255, 255, 255, 0.08);
	}

	.archive-head {
		display: grid;
		gap: 1rem;
		border-bottom: 1px solid var(--line-divider);
		padding-bottom: 1rem;
	}

	.stat-strip {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 0.5rem;
	}

	.stat-pill {
		min-width: 0;
		border-radius: 0.5rem;
		border: 1px solid rgba(255, 255, 255, 0.16);
		background: rgba(18, 16, 30, 0.42);
		padding: 0.55rem 0.7rem;
		backdrop-filter: blur(12px) saturate(1.08);
		-webkit-backdrop-filter: blur(12px) saturate(1.08);
	}

	.stat-pill span {
		display: block;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.72rem;
		font-weight: 700;
		color: rgba(255, 255, 255, 0.72);
	}

	.stat-pill strong {
		display: block;
		margin-top: 0.15rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.95rem;
		font-weight: 900;
		color: rgba(255, 255, 255, 0.96);
	}

	.active-filter-label {
		max-width: 100%;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		border-radius: 999px;
		background: var(--btn-regular-bg);
		padding: 0.25rem 0.65rem;
		font-size: 0.8rem;
		font-weight: 800;
		color: var(--primary);
	}

	.filter-row {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		padding-top: 1rem;
	}

	.filter-btn {
		height: 2.25rem;
		border-radius: 0.5rem;
		background: var(--btn-regular-bg);
		padding: 0 0.85rem;
		font-size: 0.9rem;
		font-weight: 800;
		color: var(--btn-content);
		transition:
			transform 150ms ease,
			background 150ms ease,
			color 150ms ease;
	}

	.filter-btn:hover {
		background: var(--btn-regular-bg-hover);
		color: var(--primary);
	}

	.filter-btn:active {
		transform: scale(0.97);
		background: var(--btn-regular-bg-active);
	}

	.filter-btn-active,
	.filter-btn-active:hover {
		background: var(--primary);
		color: var(--deep-text);
	}

	.query-strip {
		margin-top: 0.75rem;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		border-radius: 0.5rem;
		background: var(--btn-plain-bg-hover);
		padding: 0.55rem 0.7rem;
		font-size: 0.85rem;
		font-weight: 700;
		color: var(--btn-content);
	}

	.query-strip button {
		flex-shrink: 0;
		border-radius: 0.45rem;
		padding: 0.2rem 0.5rem;
		color: var(--primary);
		transition: background 150ms ease;
	}

	.query-strip button:hover {
		background: var(--btn-plain-bg-active);
	}

	.archive-timeline {
		padding-top: 1rem;
	}

	.empty-state {
		margin-top: 1rem;
		border-top: 1px dashed var(--line-divider);
		padding: 3rem 1rem;
		text-align: center;
	}

	.category-chip {
		max-width: 5.5rem;
		flex-shrink: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		border-radius: 0.35rem;
		background: var(--btn-regular-bg);
		padding: 0.15rem 0.4rem;
		font-weight: 800;
		color: var(--btn-content);
	}

	@media (min-width: 768px) {
		.archive-head {
			grid-template-columns: minmax(0, 1fr) minmax(24rem, 32rem);
			align-items: end;
		}

		.stat-strip {
			grid-template-columns: repeat(4, minmax(0, 1fr));
		}
	}
</style>
