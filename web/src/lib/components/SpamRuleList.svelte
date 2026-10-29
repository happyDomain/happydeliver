<script lang="ts">
    import type { SpamTestDetail } from "#lib/api/types.gen.js";
    import { formatRuleScore } from "#lib/spam.js";

    interface Props {
        rules: [string, SpamTestDetail][];
        /** Decimals of the scores, as the filter reports them. */
        digits?: number;
        /**
         * Rule to the anchor of the content finding that carries its advice. Without it the
         * list is names and numbers: a reader seeing ZERO_FONT at +1.00 has no way of knowing
         * that what to do about it is written out further down the page.
         */
        adviceAnchors?: Record<string, string>;
    }

    let { rules, digits = 1, adviceAnchors = {} }: Props = $props();

    const tone = (score: number) => (score > 0 ? "warning" : score < 0 ? "success" : undefined);
</script>

<!-- One line per rule, on the columns of the whole list: its weight, its name, what it saw. -->
<ul class="rule-lines">
    {#each rules as [name, rule] (name)}
        <li class={tone(rule.score)}>
            <span
                class="score font-monospace fw-semibold text-end {rule.score > 0
                    ? 'text-danger'
                    : rule.score < 0
                      ? 'text-success'
                      : 'text-body-secondary'}"
            >
                {formatRuleScore(rule.score, digits)}
            </span>
            <span class="name font-monospace fw-semibold">
                {name}
                {#if adviceAnchors[name]}
                    <!-- The name stays plain text: it is a name to read, not somewhere to
                         go. Only the lightbulb leads to the advice. -->
                    <a
                        class="ms-1"
                        href="#{adviceAnchors[name]}"
                        title="This rule produced a finding with advice, further down in Content Analysis"
                        aria-label="Read the advice for {name}"
                    >
                        <i class="bi bi-lightbulb" aria-hidden="true"></i>
                    </a>
                {/if}
            </span>
            <span class="about">
                {rule.description ?? ""}
                {#if rule.params}
                    <span class="params d-block font-monospace">{rule.params}</span>
                {/if}
            </span>
        </li>
    {/each}
</ul>

<style>
    .rule-lines {
        display: grid;
        grid-template-columns: max-content max-content 1fr;
        column-gap: 0.75rem;
        margin: 0 0 0.5rem;
        padding: 0;
        list-style: none;
        border: 1px solid var(--bs-border-color-translucent);
        border-radius: var(--hd-radius-md);
        font-size: 0.8125rem;
        overflow: hidden;

        li {
            --tone: transparent;
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: subgrid;
            align-items: baseline;
            padding: 0.375rem 0.75rem;
            background: color-mix(in srgb, var(--tone) 10%, transparent);

            /* As a hovered table row: over the tint, not instead of it */
            &:hover {
                box-shadow: inset 0 0 0 9999px rgba(var(--bs-emphasis-color-rgb), 0.075);
            }

            & + li {
                border-top: 1px solid var(--bs-border-color-translucent);
            }

            &.warning {
                --tone: var(--bs-warning);
            }

            &.success {
                --tone: var(--bs-success);
            }
        }

        .score {
            font-variant-numeric: tabular-nums;
        }

        .name {
            overflow-wrap: anywhere;
        }

        .about {
            min-width: 0;
            color: var(--hd-fg-2);
            overflow-wrap: anywhere;
        }

        .params {
            color: var(--hd-fg-3);
        }
    }

    /* Too narrow for three columns: what the rule saw goes under its name. */
    @media (max-width: 575.98px) {
        .rule-lines {
            grid-template-columns: max-content 1fr;

            .about {
                grid-column: 2;
            }
        }
    }
</style>
