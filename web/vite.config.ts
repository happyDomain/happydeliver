import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";
import { sveltekit } from "@sveltejs/kit/vite";

export default defineConfig({
    server: { hmr: { port: 10000 } },
    plugins: [
        sveltekit({
            // Consult https://svelte.dev/docs/kit/integrations
            // for more information about preprocessors
            preprocess: vitePreprocess(),
            adapter: adapter({ fallback: "index.html" }),
            paths: { relative: process.env.MODE === "production" },
        }),
    ],
    test: {
        expect: { requireAssertions: true },
        projects: [
            {
                extends: "./vite.config.ts",
                test: {
                    name: "server",
                    environment: "node",
                    include: ["src/**/*.{test,spec}.{js,ts}"],
                    exclude: ["src/**/*.svelte.{test,spec}.{js,ts}"],
                },
            },
        ],
    },
});
