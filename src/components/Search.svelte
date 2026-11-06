<script lang="ts">
	import { onMount, tick } from "svelte";
	import { url } from "../utils/url-utils";

	type SearchPost = { title: string; url: string; description: string; category: string; tags: string[] };
	type Result = { title: string; url: string; description: string; category?: string };
	type Pagefind = { search: (query: string) => Promise<{ results: { data: () => Promise<{ url: string; meta: { title: string }; excerpt: string }> }[] }> };
	export let posts: SearchPost[] = [];
	let dialog: HTMLDialogElement;
	let input: HTMLInputElement;
	let keyword = "";
	let results: Result[] = [];
	let searching = false;
	let requestId = 0;
	let pagefindPromise: Promise<Pagefind | null> | undefined;
	let debounce: ReturnType<typeof setTimeout>;

	async function openSearch() {
		document.getElementById("journal-mobile-menu")?.removeAttribute("open");
		if (!dialog.open) dialog.showModal();
		await tick();
		input?.focus();
	}

	function getPagefind() {
		if (!pagefindPromise) {
			const scriptUrl = url("/pagefind/pagefind.js");
			pagefindPromise = import.meta.env.PROD
				? import(/* @vite-ignore */ scriptUrl).then((module) => module as Pagefind).catch(() => null)
				: Promise.resolve(null);
		}
		return pagefindPromise;
	}

	function fallbackSearch(query: string): Result[] {
		const terms = query.toLocaleLowerCase().split(/\s+/).filter(Boolean);
		return posts.filter((post) => {
			const haystack = `${post.title} ${post.description} ${post.category} ${post.tags.join(" ")}`.toLocaleLowerCase();
			return terms.every((term) => haystack.includes(term));
		}).map((post) => ({ ...post }));
	}

	async function search(query: string) {
		const id = ++requestId;
		if (!query.trim()) { results = []; searching = false; return; }
		searching = true;
		const fallback = fallbackSearch(query.trim());
		results = fallback;
		try {
			const pagefind = await getPagefind();
			if (!pagefind) return;
			const response = await pagefind.search(query.trim());
			const data = await Promise.all(response.results.slice(0, 20).map((item) => item.data()));
			if (id !== requestId) return;
			results = data.length ? data.map((item) => ({
				title: item.meta.title,
				url: item.url,
				description: item.excerpt.replace(/<[^>]*>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">"),
			})) : fallback;
		} catch { if (id === requestId) results = fallback; }
		finally { if (id === requestId) searching = false; }
	}

	function onInput() {
		clearTimeout(debounce);
		requestId++;
		if (!keyword.trim()) { results = []; searching = false; return; }
		searching = true;
		debounce = setTimeout(() => search(keyword), 140);
	}

	function handleDialogKeydown(event: KeyboardEvent) {
		if (event.key === "Escape") {
			event.preventDefault();
			dialog.close();
			return;
		}
		if (event.key === "ArrowDown" && event.target === input) {
			const firstResult = dialog.querySelector<HTMLAnchorElement>(".result-link");
			if (firstResult) { event.preventDefault(); firstResult.focus(); }
		}
		if (event.key === "Enter" && event.target === input && results[0]) {
			window.location.href = results[0].url;
		}
	}

	onMount(() => {
		const shortcut = (event: KeyboardEvent) => {
			if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
				event.preventDefault();
				if (dialog.open) dialog.close(); else openSearch();
			}
		};
		document.addEventListener("keydown", shortcut);
		return () => { document.removeEventListener("keydown", shortcut); clearTimeout(debounce); };
	});
</script>

<button type="button" class="search-trigger" aria-label="搜索文章（Ctrl 或 Command + K）" on:click={openSearch}>
	<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>
	<span class="search-label">搜索</span><kbd>⌘ K</kbd>
</button>

<dialog bind:this={dialog} class="search-dialog" aria-label="搜索博客文章" on:keydown={handleDialogKeydown} on:click={(event) => { if (event.target === dialog) dialog.close(); }}>
	<div class="search-sheet">
		<div class="search-heading"><span>找一篇文章</span><button type="button" on:click={() => dialog.close()} aria-label="关闭搜索">Esc <span aria-hidden="true">×</span></button></div>
		<div class="search-input-row">
			<svg width="25" height="25" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>
			<label class="sr-only" for="journal-search-input">搜索文章、分类或标签</label>
			<input id="journal-search-input" bind:this={input} bind:value={keyword} on:input={onInput} type="search" placeholder="搜索文章、分类或标签…" autocomplete="off" />
		</div>
		<div class="search-content">
			{#if !keyword.trim()}
				<p class="result-caption">最近更新</p>
				{#each posts.slice(0, 4) as post}
					<a class="result-link" href={post.url}><span class="result-category">{post.category}</span><span class="result-title">{post.title}</span><span class="result-arrow" aria-hidden="true">↗</span></a>
				{/each}
			{:else}
				<p class="result-caption" aria-live="polite">{searching ? "正在查找…" : `找到 ${results.length} 篇文章`}</p>
				{#each results as result}
					<a class="result-link with-description" href={result.url}><span class="result-title">{result.title}</span><p>{result.description}</p><span class="result-arrow" aria-hidden="true">↗</span></a>
				{/each}
				{#if !searching && results.length === 0}<div class="empty-result"><span aria-hidden="true">⌕</span><p>没有找到相关内容</p><small>换个关键词试试，比如 CTF、AI 或学习笔记。</small></div>{/if}
			{/if}
		</div>
		<div class="search-footer"><span>输入标题或关键词搜索</span><span><kbd>↓</kbd> 选择 <kbd>Enter</kbd> 打开</span></div>
	</div>
</dialog>

<style>
	.search-trigger { display: inline-flex; align-items: center; gap: 9px; color: var(--muted); padding: 9px 12px; border: 1px solid var(--line); border-radius: 11px; background: var(--soft); font-size: 12px; cursor: pointer; transition: color .2s, border-color .2s; }
	.search-trigger:hover { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 45%, transparent); }
	.search-trigger kbd { padding: 1px 3px; font: 10px/1.3 monospace; color: var(--muted); margin-left: 8px; }
	.search-dialog { color: var(--ink); background: transparent; border: 0; padding: 20px; width: min(680px, 100%); max-height: calc(100dvh - 40px); overflow: visible; margin: 12vh auto auto; }
	.search-dialog::backdrop { background: #060c1caa; backdrop-filter: blur(7px); }
	.search-sheet { background: var(--surface); border: 1px solid var(--line); border-radius: 20px; overflow: hidden; box-shadow: 0 25px 90px #00000040; }
	.search-heading { display: flex; align-items: center; justify-content: space-between; padding: 24px 25px 18px; gap: 10px; }
	.search-heading > span { font-size: 18px; font-weight: 700; color: var(--ink); }
	.search-heading button { background: var(--soft); border: 0; border-radius: 9px; display: flex; align-items: center; gap: 9px; color: var(--muted); font: 11px monospace; cursor: pointer; padding: 8px 10px; }
	.search-heading button:hover { color: var(--accent); }
	.search-heading button span { font: 22px/.7 sans-serif; }
	.search-input-row { display: flex; align-items: center; gap: 12px; margin: 0 25px; border: 1px solid var(--line); border-radius: 12px; background: var(--soft); padding: 10px 14px; }
	.search-input-row:focus-within { border-color: color-mix(in srgb, var(--accent) 50%, transparent); }
	.search-input-row > svg { flex-shrink: 0; color: var(--accent); }
	.search-input-row input { width: 100%; min-width: 0; border: 0; background: transparent; color: var(--ink); font-family: inherit; font-size: 16px; line-height: 1.5; outline: 0; padding: 4px 0; box-shadow: none; }
	.search-input-row input::placeholder { color: var(--muted); font-size: 14px; }
	.search-content { padding: 20px 25px 0; max-height: min(440px, 50dvh); overflow-y: auto; overscroll-behavior: contain; }
	.result-caption { font-size: 12px; color: var(--muted); margin: 0 0 10px; }
	.result-link { display: grid; grid-template-columns: 1fr auto; position: relative; padding: 14px 36px 14px 13px; margin: 0 -6px 4px; border-radius: 12px; text-decoration: none; color: var(--ink); transition: background .15s, color .15s; }
	.result-link:hover, .result-link:focus-visible { color: var(--accent); background: var(--soft); }
	.result-category { grid-column: 1 / -1; color: var(--accent); font-size: 10px; margin-bottom: 6px; }
	.result-title { grid-column: 1; font-size: 14px; font-weight: 600; line-height: 1.7; }
	.result-arrow { position: absolute; right: 13px; top: 22px; font-size: 18px; color: var(--muted); }
	.with-description { display: block; }
	.with-description p { color: var(--muted); font-size: 12px; line-height: 1.8; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; overflow: hidden; margin: 7px 0 0; }
	.empty-result { padding: 20px 0 40px; text-align: center; }
	.empty-result > span { font-size: 40px; color: var(--accent); }
	.empty-result p { font-size: 14px; margin: 10px 0; }
	.empty-result small { color: var(--muted); font-size: 12px; }
	.search-footer { display: flex; justify-content: space-between; gap: 20px; padding: 18px 25px; margin-top: 6px; border-top: 1px solid var(--line); font-size: 11px; color: var(--muted); }
	.search-footer kbd { font-family: inherit; margin-left: 8px; }
	.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
	@media (max-width: 1000px) { .search-label, .search-trigger kbd { display: none; } .search-trigger { width: 36px; height: 36px; padding: 0; border: 0; background: transparent; justify-content: center; } }
	@media (max-width: 650px) {
		.search-dialog { padding: 20px; margin-top: 7vh; }
		.search-heading { padding: 20px 18px 15px; }
		.search-heading > span { font-size: 17px; }
		.search-input-row { margin: 0 18px; gap: 9px; padding-right: 9px; padding-left: 9px; }
		.search-input-row input { font-size: 16px; }
		.search-input-row input::placeholder { font-size: 12px; }
		.search-content { padding: 18px 18px 0; }
		.search-footer { padding: 16px 18px; font-size: 10px; }
		.search-footer > span:first-child { display: none; }
	}
</style>
