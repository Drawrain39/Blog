export interface FriendLinkItem {
	name: string;
	siteName?: string;
	url: string;
	avatar: string;
	description: string;
}

export const friendLinks: FriendLinkItem[] = [
    {
        name: "pig8086",
        siteName: "猪猪博客",
        url: "https://www.zzwl.top/",
        avatar: "/images/pig8086.jpg",
        description: " "
    },
	{
        name: "bobsers",
        siteName: "我喜欢你",
        url: "https://bobsers.top/",
        avatar: "/images/bobsers.jpg",
        description: " "
    },
	{
        name: "joker233",
        siteName: "Joker233's Blog",
        url: "https://joker233.top/",
        avatar: "/images/joker233.webp",
        description: "Aspiring to master the art of pwn."
    }

];
