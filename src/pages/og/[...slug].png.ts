import type { APIRoute, GetStaticPaths } from "astro";
import sharp from "sharp";
import path from "node:path";
import { getSortedPosts } from "../../utils/content-utils";
import { getPostVisual, visualLabels } from "../../utils/post-visuals";
import { BRAND_GEOMETRY, brandLockup } from "../../utils/brand";

export const getStaticPaths: GetStaticPaths = async () => {
  const posts = await getSortedPosts();
  return [
    { params: { slug: "index" }, props: { title: "Drawrain 的个人博客", label: "CODE / CTF / EVERYDAY", date: "drawrain.me" } },
    ...posts.map(post => ({ params: { slug: post.slug }, props: { title: post.data.title, label: visualLabels[getPostVisual(post.data)], date: post.data.published.toISOString().slice(0, 10) } })),
  ];
};
const escape = (text: string) => text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

export const GET: APIRoute = async ({ props }) => {
  const { title, label, date } = props as { title:string; label:string; date:string };
  const base = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630"><rect width="1200" height="630" fill="#171c27"/><rect x="28" y="28" width="1144" height="574" rx="26" fill="#202736" stroke="#48546a"/><path d="M67 119h1066M67 504h1066" stroke="#48546a"/><rect x="67" y="67" width="7" height="22" rx="3" fill="#75d6df"/><path d="m1059 66 7 18 18 7-18 7-7 18-7-18-18-7 18-7Z" fill="#d5a9bc"/></svg>`;
  const fontfile = path.resolve("scripts/assets/NotoSansSC.ttf");
  const titleImage = await sharp({text:{text:`<span foreground="#e4e9f2">${escape(title)}</span>`,font:"Noto Sans SC Bold 64",fontfile,width:1040,align:"left",wrap:"word-char",rgba:true}}).png().toBuffer();
  const fittedTitle = await sharp(titleImage).resize({width:1040,height:285,fit:"inside",withoutEnlargement:true}).png().toBuffer();
  const renderText = (text:string, font:string, color:string) => sharp({text:{text:`<span foreground="${color}">${escape(text)}</span>`,font:`Noto Sans SC ${font}`,fontfile,rgba:true}}).png().toBuffer();
  const brandHeight = 48;
  const brandWidth = Math.round(brandHeight * BRAND_GEOMETRY.lockup.width / BRAND_GEOMETRY.lockup.height);
  const brandSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="${brandWidth}" height="${brandHeight}" viewBox="${BRAND_GEOMETRY.lockup.viewBox}">${brandLockup({ink:"#e4e9f2",rain:"#9de0e5",star:"#d5a9bc"})}</svg>`;
  const [labelImage, brandImage, dateImage] = await Promise.all([
    renderText(label,"Medium 18","#9de0e5"), sharp(Buffer.from(brandSvg)).png().toBuffer(), renderText(date,"17","#a3aebe"),
  ]);
  const dateWidth = (await sharp(dateImage).metadata()).width || 150;
  const image = await sharp(Buffer.from(base)).composite([{input:fittedTitle,left:67,top:174},{input:labelImage,left:91,top:68},{input:brandImage,left:67,top:522},{input:dateImage,left:1132-dateWidth,top:535}]).png().toBuffer();
  return new Response(new Uint8Array(image),{headers:{"Content-Type":"image/png","Cache-Control":"public, max-age=31536000, immutable"}});
};
