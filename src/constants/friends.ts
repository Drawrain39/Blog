export interface FriendLinkItem {
	name: string;
	siteName?: string;
	url: string;
	avatar: string;
	description: string;
}

export const friendLinks: FriendLinkItem[] = [
	{
		name: "Astro",
		siteName: "astro.build",
		url: "https://astro.build/",
		avatar: "https://astro.build/assets/press/astro-icon-light-gradient.png",
		description: "Astro框架",
	},
    {
        name: "pig8086",
        siteName: "猪猪博客",
        url: "https://www.zzwl.top/",
        avatar: "/images/pig8086.jpg",
        description: " "
    },

];
