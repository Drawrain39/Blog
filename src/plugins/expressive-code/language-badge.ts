/**
 * Based on the discussion at https://github.com/expressive-code/expressive-code/issues/153#issuecomment-2282218684
 */
import { definePlugin } from "@expressive-code/core";

export function pluginLanguageBadge() {
	return definePlugin({
		name: "Language Badge",
		baseStyles: () => `
      [data-language]::before {
        position: absolute;
        z-index: 2;
        right: 3.5rem;
        top: 0.8rem;
        padding: 0.1rem 0.5rem;
        content: attr(data-language);
        font-family: "JetBrains Mono Variable", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 0.75rem;
        font-weight: bold;
        text-transform: uppercase;
        color: var(--accent);
        background: color-mix(in srgb, var(--accent) 12%, var(--codeblock-bg));
        border-radius: 0.5rem;
        pointer-events: none;
        transition: opacity 0.3s;
        opacity: 0;
      }
      .frame:not(.has-title):not(.is-terminal) {
        & pre[data-language] { padding-top: 3rem; }
        @media (hover: none) {
          & [data-language]::before {
            opacity: 1;
          }
          & [data-language]:active::before {
            opacity: 1;
          }
        }
        @media (hover: hover) {
          & [data-language]::before {
            opacity: 1;
          }
          &:hover [data-language]::before {
            opacity: 1;
          }
        }
      }
    `,
	});
}
