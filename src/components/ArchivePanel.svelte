<script lang="ts">
import { onMount } from "svelte";
import type { PostForList } from "../utils/content-utils";
import { getPostUrlBySlug } from "../utils/url-utils";

export let tags: string[] = [];
export let categories: string[] = [];
export let sortedPosts: PostForList[] = [];
export let coverImage: { src: string; srcSet: string; width: number; height: number };

let selectedTags: string[] = [...tags];
let selectedCategories: string[] = [...categories];
let uncategorized = false;
let searchQuery = "";

const normalize = (value: string | null | undefined) => (value || "").trim().toLocaleLowerCase();
const dateOf = (value: Date | string | number) => new Date(value);
const fullDate = (value: Date | string | number) => dateOf(value).toISOString().slice(0, 10);

$: categoryNames = [...new Set(sortedPosts.map((post) => post.data.category).filter((value): value is string => Boolean(value)))];
$: allWords = sortedPosts.reduce((total, post) => total + (post.wordCount || 0), 0);
$: wordsLabel = allWords >= 10000 ? `${(allWords / 10000).toFixed(1)} 万` : allWords.toLocaleString("zh-CN");
$: latestDate = sortedPosts.length ? fullDate(sortedPosts.reduce((latest, post) => Math.max(latest, dateOf(post.data.updated || post.data.published).getTime()), 0)) : "—";
$: hasFilters = Boolean(selectedTags.length || selectedCategories.length || uncategorized || searchQuery.trim());
$: filteredPosts = sortedPosts.filter((post) => {
	if (selectedCategories.length && !selectedCategories.some((category) => normalize(category) === normalize(post.data.category))) return false;
	if (selectedTags.length && !selectedTags.some((tag) => post.data.tags.some((postTag) => normalize(tag) === normalize(postTag)))) return false;
	if (uncategorized && post.data.category) return false;
	const text = [post.data.title, post.data.description, post.data.category, ...post.data.tags].join(" ");
	return normalize(text).includes(normalize(searchQuery));
});
$: groupedPosts = filteredPosts.reduce((groups, post) => {
	const year = dateOf(post.data.published).getUTCFullYear();
	(groups[year] ||= []).push(post);
	return groups;
}, {} as Record<number, PostForList[]>);
$: years = Object.keys(groupedPosts).map(Number).sort((a, b) => b - a);

function readFilters() {
	const params = new URLSearchParams(window.location.search);
	const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
	selectedTags = [...params.getAll("tag"), ...hashParams.getAll("tag")].map((value) => value.trim()).filter(Boolean);
	selectedCategories = [...params.getAll("category"), ...hashParams.getAll("category")].map((value) => value.trim()).filter(Boolean);
	uncategorized = params.has("uncategorized") || hashParams.has("uncategorized");
}

function setCategory(category: string | null) {
	selectedCategories = category ? [category] : [];
	selectedTags = [];
	uncategorized = false;
	searchQuery = "";
	const nextUrl = new URL(window.location.href);
	for (const key of ["category", "tag", "uncategorized"]) nextUrl.searchParams.delete(key);
	if (category) nextUrl.searchParams.set("category", category);
	if (/^#(?:category|tag|uncategorized)=/.test(nextUrl.hash)) nextUrl.hash = "";
	window.history.replaceState(null, "", `${nextUrl.pathname}${nextUrl.search}${nextUrl.hash}`);
}

onMount(() => {
	readFilters();
	window.addEventListener("popstate", readFilters);
	window.addEventListener("hashchange", readFilters);
	return () => {
		window.removeEventListener("popstate", readFilters);
		window.removeEventListener("hashchange", readFilters);
	};
});
</script>

<div class="archive-page">
	<header class="archive-cover">
		<img class="cover-art" src={coverImage.src} srcset={coverImage.srcSet} sizes="(max-width: 760px) calc(100vw - 32px), (max-width: 1304px) calc(100vw - 64px), 1240px" width={coverImage.width} height={coverImage.height} alt="暮色中的城市天际线与回望的少女" loading="eager" decoding="async" />
		<div class="cover-shade"></div>
		<div class="cover-copy"><span class="page-location">首页 / 归档</span><span class="archive-label" aria-hidden="true">✦ ARCHIVES</span><h1>文章归档 <span aria-hidden="true">✧</span></h1><p>CTF 题解、学习笔记和日常记录</p></div>
	</header>
	<div class="archive-stats" aria-label="归档统计">
		<div><svg class="stat-icon" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true" focusable="false"><path d="M17 7h22l11 11v38H17zM39 7v12h11M25 29h17M25 37h17M25 45h11" stroke-linejoin="round" stroke-linecap="round"/></svg><strong>{sortedPosts.length}</strong><span>篇文章</span></div>
		<div><svg class="stat-icon" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true" focusable="false"><path d="M13 16V9h38v7M32 9v45M23 54h18M14 25h7M14 34h7M14 43h7M43 25h7M43 34h7M43 43h7" stroke-linecap="round" stroke-linejoin="round"/></svg><strong>{wordsLabel}</strong><span>累计字数</span></div>
		<div><svg class="stat-icon" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true" focusable="false"><rect x="10" y="10" width="18" height="18" rx="4"/><rect x="36" y="10" width="18" height="18" rx="4"/><rect x="10" y="36" width="18" height="18" rx="4"/><rect x="36" y="36" width="18" height="18" rx="4"/></svg><strong>{categoryNames.length}</strong><span>个分类</span></div>
		<div class="latest-stat"><svg class="stat-icon" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true" focusable="false"><rect x="10" y="14" width="44" height="41" rx="5"/><path d="M10 26h44M21 8v12M43 8v12M20 36h5M30 36h5M40 36h5M20 45h5M30 45h5" stroke-linecap="round"/></svg><strong>{latestDate}</strong><span>最近更新</span></div>
	</div>
	<section class="archive-panel" aria-label="文章列表">
		<div class="archive-toolbar">
			<div class="archive-filters" role="group" aria-label="按分类筛选文章">
				<button type="button" class:active={!selectedCategories.length && !selectedTags.length && !uncategorized} aria-pressed={!selectedCategories.length && !selectedTags.length && !uncategorized} on:click={() => setCategory(null)}>全部 <span>{sortedPosts.length}</span></button>
				{#each categoryNames as category}<button type="button" class:active={selectedCategories.includes(category)} aria-pressed={selectedCategories.includes(category)} on:click={() => setCategory(category)}>{category} <span>{sortedPosts.filter((post) => post.data.category === category).length}</span></button>{/each}
			</div>
			<label class="archive-search"><span aria-hidden="true">⌕</span><input type="search" aria-label="搜索归档中的文章" placeholder="搜索文章…" bind:value={searchQuery} /></label>
		</div>
		<div class="archive-result-note" aria-live="polite"><span>{selectedTags.length ? selectedTags.map((tag) => `#${tag}`).join(" / ") : uncategorized ? "未分类" : selectedCategories.join(" / ") || "全部文章"} · {filteredPosts.length} 篇</span>{#if hasFilters}<button type="button" on:click={() => setCategory(null)}>清除筛选 ×</button>{:else}<span>最新发布在前</span>{/if}</div>
		{#if !filteredPosts.length}
			<div class="empty-archive"><span aria-hidden="true">⌕</span><h2>没有找到相关的文章</h2><p>试试其他关键词，或者清除筛选条件。</p><button type="button" on:click={() => setCategory(null)}>查看全部文章</button></div>
		{:else}
			<div class="archive-years">
				{#each years as year}
					<section class="year-section" aria-labelledby={`archive-year-${year}`}><div class="year-heading"><h2 id={`archive-year-${year}`}>{year} 年</h2><span>{groupedPosts[year].length} 篇文章</span></div><div class="year-posts">{#each groupedPosts[year] as post}<a class="archive-entry" href={getPostUrlBySlug(post.slug)}><time datetime={fullDate(post.data.published)}>{fullDate(post.data.published).slice(5).replace("-", ".")}</time><div class="entry-copy"><h3>{post.data.title}</h3><p>{post.data.tags.slice(0, 3).map((tag) => `#${tag}`).join("  ")}</p></div><span class="entry-category">{post.data.category || "未分类"}</span><span class="entry-arrow" aria-hidden="true">→</span></a>{/each}</div></section>
				{/each}
			</div>
		{/if}
	</section>
</div>

<style>
	.archive-page { padding-top: 30px; }
	.archive-cover { position: relative; min-height: 245px; overflow: hidden; border-radius: 24px; border: 1px solid var(--line); background: var(--surface); }
	.cover-art { position: absolute; inset: 0; height: 100%; width: 100%; object-fit: cover; object-position: center 19%; }
	.cover-shade { position: absolute; inset: 0; background: linear-gradient(270deg,#152331d9,#15233166 42%,#15233100 72%),linear-gradient(0deg,#111c2d77,transparent 80%); }
	.cover-copy { position: relative; width: 44%; margin-left: auto; padding: 30px 38px; color: #edf4fc; }
	.page-location { color: #c6d8e6; font-size: 11px; }
	.archive-label { display: block; margin-top: 20px; margin-bottom: 7px; color: #c6d8e6; font: 500 10px/1.4 var(--font-mono); letter-spacing: .16em; }
	.cover-copy h1 { font-size: 38px; font-weight: 700; margin: 0 0 10px; color: #f4f8ff; text-shadow: 0 2px 12px #0c162c66; }
	.cover-copy h1 > span { color: #b7d9ff; font-size: 25px; vertical-align: middle; }
	.cover-copy p { color: #d3e0eb; font-size: 13px; }
	.archive-stats { display: grid; grid-template-columns: repeat(3, 1fr) 1.3fr; gap: 15px; margin: 22px 0; }
	.archive-stats > div { position: relative; isolation: isolate; overflow: hidden; display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 0; padding: 22px 15px; border: 1px solid color-mix(in srgb, var(--accent) 15%, var(--line)); border-radius: 16px; background: linear-gradient(140deg, color-mix(in srgb, var(--surface) 92%, transparent), color-mix(in srgb, var(--surface) 76%, transparent)); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); box-shadow: inset 0 1px 0 #ffffff08; transition: border-color .2s, box-shadow .2s; }
	.archive-stats > div::before { content: ""; position: absolute; top: 0; left: 14px; right: 14px; height: 1px; background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--accent) 32%, transparent), transparent); pointer-events: none; }
	.archive-stats > div::after { content: ""; position: absolute; inset: 0; z-index: -1; border-radius: inherit; background: radial-gradient(ellipse at 85% 0, color-mix(in srgb, var(--accent) 10%, transparent), transparent 70%); opacity: 0; transition: opacity .2s; pointer-events: none; }
	.archive-stats .stat-icon { position: absolute; right: -10px; bottom: -11px; z-index: -1; width: 84px; height: 84px; color: var(--accent); opacity: .12; pointer-events: none; }
	.archive-stats strong { position: relative; color: var(--accent); font-size: clamp(30px, 3vw, 38px); line-height: 1.2; font-weight: 800; letter-spacing: -.035em; font-variant-numeric: tabular-nums; }
	.archive-stats span { position: relative; font-size: 12px; color: var(--muted); margin-top: 10px; }
	@media (hover: hover) and (pointer: fine) { .archive-stats > div:hover { border-color: color-mix(in srgb, var(--accent) 36%, var(--line)); box-shadow: inset 0 1px 0 #ffffff0a, 0 5px 22px color-mix(in srgb, var(--accent) 7%, transparent); } .archive-stats > div:hover::after { opacity: 1; } }
	@media (prefers-reduced-motion: reduce) { .archive-stats > div, .archive-stats > div::after { transition: none; } }
	.archive-stats .latest-stat strong { font-size: clamp(20px, 2.1vw, 26px); font-weight: 750; letter-spacing: -.025em; }
	.archive-panel { background: var(--surface); border: 1px solid var(--line); border-radius: 20px; padding: 28px; }
	.archive-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
	.archive-filters { display: flex; flex-wrap: wrap; gap: 7px; }
	.archive-filters button { padding: 6px 11px; border-radius: 9px; border: 1px solid transparent; font-size: 12px; transition: background .2s, color .2s; color: var(--muted); background: var(--soft); }
	.archive-filters button:hover { color: var(--accent); }
	.archive-filters button.active { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 35%, transparent); background: color-mix(in srgb, var(--accent) 10%, var(--surface)); }
	.archive-filters button span { font-size: 10px; margin-left: 4px; opacity: .9; }
	.archive-search { display: flex; align-items: center; gap: 7px; flex: 0 0 190px; min-width: 0; border: 1px solid var(--line); border-radius: 10px; padding: 7px 12px; background: var(--paper); color: var(--muted); }
	.archive-search > span { font-size: 22px; line-height: 1; }
	.archive-search input { width: 100%; min-width: 0; background: transparent; font-size: 12px; color: var(--ink); border: 0; outline-offset: 5px; }
	.archive-search input::placeholder { color: var(--muted); }
	.archive-result-note { display: flex; justify-content: space-between; gap: 20px; color: var(--muted); font-size: 11px; padding: 21px 0 18px; margin-bottom: 6px; border-bottom: 1px solid var(--line); }
	.archive-result-note button { color: var(--accent); }
	.year-section { padding: 17px 0 15px; }
	.year-heading { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; }
	.year-heading::before { content: ""; width: 9px; height: 9px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 0 5px color-mix(in srgb, var(--accent) 10%, transparent); margin: 0 5px; }
	.year-heading h2 { font-size: 22px; font-weight: 600; }
	.year-heading > span { font-size: 11px; color: var(--muted); }
	.year-posts { border-left: 1px solid var(--line); margin-left: 9px; padding-left: 24px; }
	.archive-entry { position: relative; display: flex; align-items: center; gap: 18px; min-width: 0; padding: 19px 10px; border-bottom: 1px solid var(--line); transition: color .2s, background .2s; border-radius: 9px; }
	.archive-entry::before { content: ""; position: absolute; left: -28px; top: 28px; width: 7px; height: 7px; border: 2px solid var(--muted); border-radius: 50%; background: var(--surface); }
	.archive-entry:last-child { border-bottom-color: transparent; }
	.archive-entry time { color: var(--muted); font-size: 11px; flex: 0 0 42px; }
	.entry-copy { flex: 1; min-width: 0; }
	.entry-copy h3 { font-size: 15px; font-weight: 500; line-height: 1.7; transition: color .2s; }
	.entry-copy p { color: var(--muted); font-size: 10px; margin-top: 6px; overflow-wrap: anywhere; }
	.entry-category { font-size: 10px; color: var(--accent); flex-shrink: 0; border-radius: 6px; background: var(--soft); padding: 4px 9px; }
	.entry-arrow { color: var(--muted); font-size: 20px; flex-shrink: 0; transition: transform .2s, color .2s; }
	.archive-entry:hover { background: color-mix(in srgb, var(--accent) 3%, var(--surface)); }
	.archive-entry:hover h3, .archive-entry:hover .entry-arrow { color: var(--accent); }
	.archive-entry:hover::before { border-color: var(--accent); }
	.archive-entry:hover .entry-arrow { transform: translateX(3px); }
	.empty-archive { text-align: center; padding: 4rem 1rem; }
	.empty-archive > span { font-size: 48px; color: var(--accent); }
	.empty-archive h2 { font-size: 19px; font-weight: 500; margin: 1rem 0; }
	.empty-archive p { font-size: 13px; color: var(--muted); }
	.empty-archive button { color: var(--accent); font-size: 12px; margin-top: 1.5rem; padding: 8px 15px; background: var(--soft); border-radius: 9px; }
	@media (max-width: 900px) { .archive-toolbar { flex-wrap: wrap; } .archive-search { flex-basis: 100%; } .entry-category { display: none; } .archive-stats .latest-stat strong { font-size: 20px; } }
	@media (max-width: 760px) { .cover-copy { width: 52%; padding: 30px 24px; } .cover-copy h1 { font-size: 32px; } .cover-copy p { font-size: 12px; } .cover-art { object-position: 30% 15%; } }
	@media (max-width: 600px) { .archive-page { padding-top: 20px; } .archive-cover { min-height: 225px; border-radius: 18px; } .cover-copy { padding: 25px; } .cover-copy h1 { font-size: 32px; } .archive-stats { grid-template-columns: 1fr 1fr; gap: 12px; margin: 17px 0; } .archive-stats > div { padding: 22px 12px; } .archive-stats strong { font-size: 32px; } .archive-stats .latest-stat strong { font-size: 22px; } .archive-panel { padding: 20px 16px; } .archive-filters { gap: 6px; } .archive-filters button { padding: 6px 8px; font-size: 11px; } .year-heading h2 { font-size: 21px; } .year-posts { padding-left: 15px; margin-left: 8px; } .archive-entry { gap: 12px; padding: 17px 0 17px 6px; } .archive-entry::before { left: -19px; } .entry-copy h3 { font-size: 13px; } .archive-entry time { font-size: 10px; flex-basis: 33px; } .entry-arrow { display: none; } }
	@media (max-width: 600px) { .cover-copy { width: 100%; padding: 80px 25px 24px; } .page-location { display: none; } .archive-label { margin-top: 0; } .cover-shade { background: linear-gradient(0deg,#112236eb,#11223633 75%,transparent); } }
</style>
