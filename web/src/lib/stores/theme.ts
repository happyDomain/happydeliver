import { writable } from "svelte/store";
import { browser } from "$app/environment";

const getInitialTheme = () => {
    if (!browser) return "light";

    const stored = localStorage.getItem("theme");
    if (stored) return stored;

    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
};

export const theme = writable<"light" | "dark">(getInitialTheme());

theme.subscribe((value) => {
    if (browser) {
        localStorage.setItem("theme", value);
        document.documentElement.setAttribute("data-bs-theme", value);
    }
});
