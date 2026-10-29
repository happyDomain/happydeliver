/**
 * Folded sections and checks must not hide what a link points at.
 *
 * The report folds what passed into closed <details>, and every summary, score and finding
 * links to the evidence by its anchor. Following such a link to an element inside a closed
 * <details> would scroll to a box that shows nothing: the ancestors are opened first.
 * Chromium does this by itself for fragment navigation, other engines do not yet.
 */
export function revealElement(target: Element | null): void {
    for (let node = target; node; node = node.parentElement) {
        if (node instanceof HTMLDetailsElement && !node.open) node.open = true;
    }
}

/** Opens the element the given fragment ("#dns-spf") names, if there is one. */
export function revealHash(hash: string): Element | null {
    if (!hash || hash === "#") return null;

    let id: string;
    try {
        id = decodeURIComponent(hash.slice(1));
    } catch {
        return null;
    }

    const target = document.getElementById(id);
    if (target) {
        revealElement(target);
        // A <details> named by the fragment is itself the thing to show.
        if (target instanceof HTMLDetailsElement) target.open = true;
    }
    return target;
}

/**
 * Keeps in-page links working across folded content, for as long as the returned function
 * is not called. Clicks are caught before the browser scrolls, so the target is already
 * unfolded when it does.
 */
export function revealOnNavigation(): () => void {
    const onClick = (event: MouseEvent) => {
        const link = (event.target as Element | null)?.closest?.("a[href^='#']");
        if (link) revealHash(link.getAttribute("href") ?? "");
    };
    const onHashChange = () => revealHash(window.location.hash);

    document.addEventListener("click", onClick, true);
    window.addEventListener("hashchange", onHashChange);

    return () => {
        document.removeEventListener("click", onClick, true);
        window.removeEventListener("hashchange", onHashChange);
    };
}
