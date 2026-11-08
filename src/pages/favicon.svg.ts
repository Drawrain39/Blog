import type { APIRoute } from "astro";
import { BRAND_GEOMETRY, brandMark } from "../utils/brand";

export const prerender = true;

export const GET: APIRoute = () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="18" fill="#171c27"/><svg x="6" y="6" width="52" height="52" viewBox="${BRAND_GEOMETRY.mark.viewBox}">${brandMark({ink:"#e4e9f2",rain:"#9de0e5",star:"#d5a9bc"})}</svg></svg>`;
  return new Response(svg, {
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
    },
  });
};
