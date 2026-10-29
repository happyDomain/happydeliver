<script lang="ts">
    import type { Issue, SpfRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        spfRecords?: SpfRecord[];
        issues?: Issue[];
    }

    let { spfRecords, issues }: Props = $props();

    const spfIsValid = $derived(spfRecords?.every((r) => r.valid) ?? false);

    // Where a record sits decides what its "all" means: at the top, or reached through
    // redirect=, it is the verdict for every other server; inside an include it only
    // says the include did not match, and the including record carries on.
    type Role = "root" | "include" | "redirect";

    interface Term {
        token: string;
        hint: string;
        tone?: "pass" | "fail" | "soft" | "neutral";
        child?: SpfNode;
    }

    interface SpfNode {
        record: SpfRecord;
        role: Role;
        terms: Term[];
    }

    const finalVerdicts: Record<string, string> = {
        "-": "every other server fails",
        "~": "every other server soft-fails",
        "?": "nothing said about other servers",
        "+": "every server passes",
    };

    // One generic line per kind of term: the token next to it already shows the
    // domain or address it applies to.
    const mechanismHints: Record<string, string> = {
        include: "servers allowed by another domain's SPF record",
        redirect: "when nothing matched, another domain's SPF record decides",
        ip4: "an IPv4 address or range",
        ip6: "an IPv6 address or range",
        a: "the addresses of the domain (A/AAAA records)",
        mx: "the mail servers of the domain (MX records)",
        ptr: "servers whose reverse DNS is under the domain (deprecated)",
        exists: "any server, as long as the domain resolves",
        exp: "where to find the text explaining a rejection",
    };

    const qualifierResults: Record<string, string> = {
        "+": "passes",
        "-": "fails",
        "~": "soft-fails",
        "?": "is neutral",
    };

    const tones: Record<string, Term["tone"]> = {
        "-": "fail",
        "~": "soft",
        "?": "neutral",
        "+": "pass",
    };

    // The SPF records come flat, in the order the analyzer followed them: the sender's
    // record first, then each include or redirect target right after the record that
    // names it. Matching names to domains is enough to rebuild the tree.
    function buildNode(
        record: SpfRecord,
        role: Role,
        byDomain: Map<string, SpfRecord>,
        ancestors: Set<string>,
        reached: Set<SpfRecord>,
    ): SpfNode {
        reached.add(record);
        const domain = record.domain ?? "";
        // eslint-disable-next-line svelte/prefer-svelte-reactivity -- local to the computation, not state
        const path = new Set(ancestors).add(domain.toLowerCase());
        const terms: Term[] = [];

        for (const token of (record.record ?? "").split(/\s+/)) {
            if (!token || /^v=spf1$/i.test(token)) continue;

            const qualifier = /^[-~?+]/.test(token) ? token[0] : "+";
            const body = /^[-~?+]/.test(token) ? token.slice(1) : token;
            const [rawName, rawValue] = body.split(/[:=](.*)/s);
            // "a/24", "mx/24": the CIDR length does not change what the term is
            const name = rawName.split("/")[0].toLowerCase();
            const value = rawValue || undefined;

            const nested = (childRole: Role) => {
                if (!value || path.has(value.toLowerCase())) return undefined;
                const child = byDomain.get(value.toLowerCase());
                return child ? buildNode(child, childRole, byDomain, path, reached) : undefined;
            };

            let term: Term;
            switch (name) {
                case "all":
                    term = {
                        token,
                        // +all lets anyone through: never shown as good news
                        tone:
                            role === "include"
                                ? undefined
                                : qualifier === "+"
                                  ? "fail"
                                  : tones[qualifier],
                        hint:
                            role === "include"
                                ? qualifier === "+"
                                    ? "matches every server, so the include always passes"
                                    : "no match here: the including record carries on"
                                : finalVerdicts[qualifier],
                    };
                    break;
                case "include":
                    term = { token, hint: mechanismHints.include, child: nested("include") };
                    break;
                case "redirect":
                    term = { token, hint: mechanismHints.redirect, child: nested("redirect") };
                    break;
                default:
                    term = { token, hint: mechanismHints[name] ?? "unknown term" };
            }

            if (name !== "all" && name !== "redirect" && name !== "exp") {
                term.tone = qualifier === "+" ? undefined : tones[qualifier];
                term.hint += `; a match ${qualifierResults[qualifier]}`;
            }
            terms.push(term);
        }

        return { record, role, terms };
    }

    const trees = $derived.by(() => {
        if (!spfRecords?.length) return [];

        // eslint-disable-next-line svelte/prefer-svelte-reactivity -- local to the computation, not state
        const byDomain = new Map<string, SpfRecord>();
        for (const r of spfRecords) {
            const key = r.domain?.toLowerCase();
            if (key && !byDomain.has(key)) byDomain.set(key, r);
        }

        const reached = new Set<SpfRecord>();
        const roots = [buildNode(spfRecords[0], "root", byDomain, new Set(), reached)];
        // Whatever the tree could not place stays visible rather than silently dropped
        for (const r of spfRecords) {
            if (!reached.has(r)) roots.push(buildNode(r, "include", byDomain, new Set(), reached));
        }
        return roots;
    });

    // Condensed: the raw records, hung under the record that includes them. Detailed:
    // every record taken apart term by term, with what each term means.
    let detailed = $state(false);

    function branches(node: SpfNode): SpfNode[] {
        return node.terms.flatMap((t) => (t.child ? [t.child] : []));
    }
</script>

{#snippet rawNode(node: SpfNode)}
    <div class="spf-raw-row">
        <span class="fw-semibold">{node.record.domain ?? ""}</span>
        {#if node.role === "redirect"}<span class="small text-body-secondary">redirect</span>{/if}
        {#if node.record.record}<code>{node.record.record}</code>{/if}
    </div>
    {#if node.record.error}
        <div class="small text-danger">{node.record.error}</div>
    {/if}
    {#if branches(node).length > 0}
        <ul class="spf-branches">
            {#each branches(node) as child, i (i)}
                <li>{@render rawNode(child)}</li>
            {/each}
        </ul>
    {/if}
{/snippet}

{#snippet spfNode(node: SpfNode)}
    <div class="spf-domain">
        <span class="font-monospace">{node.record.domain ?? ""}</span>
    </div>
    {#if node.record.error}
        <div class="small text-danger">{node.record.error}</div>
    {/if}
    {#if node.terms.length > 0}
        <ul class="spf-terms">
            {#each node.terms as term, i (i)}
                <li>
                    <code class="spf-token" data-tone={term.tone}>{term.token}</code>
                    <span class="spf-hint">{term.hint}</span>
                    {#if term.child}
                        <div class="spf-nested">{@render spfNode(term.child)}</div>
                    {/if}
                </li>
            {/each}
        </ul>
    {/if}
{/snippet}

{#if spfRecords && spfRecords.length > 0}
    <CheckCard
        id="dns-spf"
        title="Sender Policy Framework"
        tag="SPF"
        status={spfIsValid ? "pass" : "fail"}
        summary={spfRecords[0].record ?? spfRecords[0].error}
        summaryFoldedOnly={!!spfRecords[0].record}
        docs={[docs.spf, docs.spfAll, docs.spfLookupLimit]}
        {issues}
    >
        <div class="card-body">
            {#each trees as tree, i (i)}
                <div class="spf-tree">
                    {#if i === 0}
                        <div
                            class="spf-view btn-group btn-group-sm"
                            role="group"
                            aria-label="SPF view"
                        >
                            <button
                                type="button"
                                class="btn btn-outline-secondary"
                                class:active={!detailed}
                                aria-pressed={!detailed}
                                onclick={() => (detailed = false)}>Condensed</button
                            >
                            <button
                                type="button"
                                class="btn btn-outline-secondary"
                                class:active={detailed}
                                aria-pressed={detailed}
                                onclick={() => (detailed = true)}>Detailed</button
                            >
                        </div>
                    {/if}
                    {#if detailed}{@render spfNode(tree)}{:else}{@render rawNode(tree)}{/if}
                </div>
            {/each}
            <p class="check-about">
                SPF lists the servers allowed to send mail for the envelope sender domain. Receivers
                check the sending IP against it, term by term, and the first one that matches
                decides; an include only matches when the included record lets the server pass.
            </p>
        </div>
    </CheckCard>
{/if}

<style lang="scss">
    // Out of the way until the frame is hovered or the buttons are reached by keyboard;
    // where nothing can hover, it simply stays.
    .spf-view {
        position: absolute;
        top: 0.375rem;
        right: 0.375rem;
        z-index: 1;
        background: var(--hd-bg-default);
        border-radius: var(--hd-radius);
        opacity: 0;
        transition: opacity 0.15s ease-in-out;

        .spf-tree:hover > &,
        &:focus-within {
            opacity: 1;
        }

        @media (hover: none) {
            opacity: 1;
        }
    }

    .spf-raw-row {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        column-gap: 0.75rem;
        row-gap: 0.125rem;
        padding-block: 0.125rem;

        code {
            background: var(--hd-bg-default);
            overflow-wrap: anywhere;
        }
    }

    // Right-angled tree lines: each branch gets an elbow from its parent's trunk to its
    // first row, and the trunk runs on past every branch but the last.
    .spf-branches {
        --spf-line: 1px solid var(--hd-border-3);
        --spf-elbow: 0.95em;

        margin: 0 0 0 0.5rem;
        padding: 0;
        list-style: none;

        > li {
            position: relative;
            padding-left: 1.5rem;

            &::before {
                content: "";
                position: absolute;
                left: 0;
                top: 0;
                width: 1.125rem;
                height: var(--spf-elbow);
                border-left: var(--spf-line);
                border-bottom: var(--spf-line);
            }

            &:not(:last-child)::after {
                content: "";
                position: absolute;
                left: 0;
                top: var(--spf-elbow);
                bottom: 0;
                border-left: var(--spf-line);
            }
        }
    }

    .spf-tree {
        position: relative;
        margin-bottom: 0.75rem;
        padding: 0.5rem 0.75rem;
        background: var(--hd-bg-subtle);
        border: 1px solid var(--hd-border-1);
        border-radius: var(--hd-radius);
    }

    .spf-domain {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        column-gap: 0.75rem;
        font-weight: 600;
    }

    // Tokens in one column, what they mean in the next; a nested record spans both.
    .spf-terms {
        display: grid;
        grid-template-columns: minmax(0, max-content) 1fr;
        column-gap: 1rem;
        row-gap: 0.25rem;
        margin: 0.25rem 0 0;
        padding: 0;
        list-style: none;

        > li {
            display: contents;
        }
    }

    .spf-token {
        justify-self: start;
        background: var(--hd-bg-default);
        overflow-wrap: anywhere;

        &[data-tone="fail"] {
            color: var(--hd-danger-text);
        }

        &[data-tone="soft"],
        &[data-tone="neutral"] {
            color: var(--hd-warning-text);
        }

        &[data-tone="pass"] {
            color: var(--hd-success-text);
        }
    }

    .spf-hint {
        color: var(--hd-fg-3);
        font-size: 0.875em;
        align-self: center;
    }

    .spf-nested {
        grid-column: 1 / -1;
        margin: 0.125rem 0 0.25rem 0.5rem;
        padding-left: 0.75rem;
        border-left: 2px solid var(--hd-border-2);
    }
</style>
