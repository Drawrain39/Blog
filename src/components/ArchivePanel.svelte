<script lang="ts">
import { onMount } from "svelte";
import type { PostForList } from "../utils/content-utils";
import { getPostUrlBySlug, url } from "../utils/url-utils";

export let tags: string[] = [];
export let categories: string[] = [];
export let sortedPosts: PostForList[] = [];

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
		<img class="cover-art" src={url("/images/re2.jpg")} alt="夜空烟花下的少女" />
		<div class="cover-shade"></div>
		<div class="cover-copy"><span class="page-location">首页 / 归档</span><h1>文章归档 <span aria-hidden="true">✧</span></h1><p>CTF 题解、学习笔记和日常记录</p></div>
	</header>
	<div class="archive-stats" aria-label="归档统计"><div><strong>{sortedPosts.length}</strong><span>篇文章</span></div><div><strong>{wordsLabel}</strong><span>累计字数</span></div><div><strong>{categoryNames.length}</strong><span>个分类</span></div><div class="latest-stat"><strong>{latestDate}</strong><span>最近更新</span></div></div>
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
	.cover-art { position: absolute; inset: 0; height: 100%; width: 100%; object-fit: cover; object-position: center 35%; }
	.cover-shade { position: absolute; inset: 0; background: linear-gradient(90deg, color-mix(in srgb, var(--surface) 95%, transparent), color-mix(in srgb, var(--surface) 20%, transparent) 95%), linear-gradient(0deg, var(--surface), transparent 85%); }
	.cover-copy { position: relative; padding: 38px; }
	.page-location { color: var(--muted); font-size: 11px; }
	.cover-copy h1 { font-size: 38px; font-weight: 700; margin: 23px 0 10px; color: var(--ink); }
	.cover-copy h1 > span { color: var(--accent); font-size: 25px; vertical-align: middle; }
	.cover-copy p { color: var(--muted); font-size: 13px; }
	.archive-stats { display: grid; grid-template-columns: repeat(3, 1fr) 1.3fr; gap: 15px; margin: 22px 0; }
	.archive-stats > div { display: flex; flex-direction: column; align-items: center; padding: 18px 15px; border: 1px solid var(--line); border-radius: 16px; background: var(--surface); }
	.archive-stats strong { color: var(--accent); font-size: 27px; line-height: 1.3; font-weight: 600; }
	.archive-stats span { font-size: 11px; color: var(--muted); margin-top: 8px; }
	.archive-stats .latest-stat strong { font-size: 22px; padding-top: 4px; }
	.archive-panel { background: var(--surface); border: 1px solid var(--line); border-radius: 20px; padding: 28px; }
	.archive-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
	.archive-filters { display: flex; flex-wrap: wrap; gap: 7px; }
	.archive-filters button { padding: 6px 11px; border-radius: 9px; border: 1px solid transparent; font-size: 12px; transition: background .2s, color .2s; color: var(--muted); background: var(--soft); }
	.archive-filters button:hover { color: var(--accent); }
	.archive-filters button.active { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 35%, transparent); background: color-mix(in srgb, var(--accent) 10%, var(--surface)); }
	.archive-filters button span { font-size: 10px; margin-left: 4px; opacity: .7; }
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
	@media (max-width: 900px) { .archive-toolbar { flex-wrap: wrap; } .archive-search { flex-basis: 100%; } .entry-category { display: none; } .archive-stats .latest-stat strong { font-size: 19px; } }
	@media (max-width: 600px) { .archive-page { padding-top: 20px; } .archive-cover { min-height: 225px; border-radius: 18px; } .cover-copy { padding: 25px; } .cover-copy h1 { font-size: 32px; } .archive-stats { grid-template-columns: 1fr 1fr; gap: 12px; margin: 17px 0; } .archive-stats strong { font-size: 25px; } .archive-stats .latest-stat strong { font-size: 21px; } .archive-panel { padding: 20px 16px; } .archive-filters { gap: 6px; } .archive-filters button { padding: 6px 8px; font-size: 11px; } .year-heading h2 { font-size: 21px; } .year-posts { padding-left: 15px; margin-left: 8px; } .archive-entry { gap: 12px; padding: 17px 0 17px 6px; } .archive-entry::before { left: -19px; } .entry-copy h3 { font-size: 13px; } .archive-entry time { font-size: 10px; flex-basis: 33px; } .entry-arrow { display: none; } }
</style>
