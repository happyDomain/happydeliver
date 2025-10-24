<script lang="ts">
    import type { Snippet } from "svelte";
    import type { ClassValue } from "svelte/elements";

    import { appConfig } from "$lib/config";

    interface Props {
        class: ClassValue;
        question?: Snippet;
        source?: string;
    }

    let { class: className, question, source }: Props = $props();

    let step = $state<number>(0);

    interface Responses {
        id: string;
        stars: number;
        source?: string;
        avis?: string;
    }

    const responses = $state<Responses>({
        id: btoa(String(Math.random() * 100)),
        stars: 1,
    });

    function submit(e: SubmitEvent): void {
        e.preventDefault();

        step += 1;

        if (source) {
            responses.source = source;
        }

        if ($appConfig.surveyUrl) {
            fetch($appConfig.surveyUrl, {
                method: "POST",
                body: JSON.stringify(responses),
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
            });
        }
    }
</script>

{#if $appConfig.surveyUrl}
    <form class={className} onsubmit={submit}>
        {#if step === 0}
            {#if question}{@render question()}{:else}
                <p class="mb-1 small">Help us to design a better tool, rate this report!</p>
            {/if}
            <div class="btn-group" role="group" aria-label="Rate your level of happyness">
                {#each [...Array(5).keys()] as i}
                    <button
                        class="btn btn-lg px-1 pb-2 pt-1"
                        class:btn-outline-success={responses.stars <= i}
                        class:text-dark={responses.stars <= i}
                        class:btn-success={responses.stars > i}
                        style="line-height: 1em"
                        onfocusin={() => (responses.stars = i + 1)}
                        onmouseenter={() => (responses.stars = i + 1)}
                        aria-label={`${i + 1} star${i + 1 > 1 ? "s" : ""}`}
                    >
                        <i class="bi bi-star-fill"></i>
                    </button>
                {/each}
            </div>
        {:else if step === 1}
            <p>
                {#if responses.stars == 5}Thank you! Would you like to tell us more?
                {:else if responses.stars == 4}What are we missing to earn 5 stars?
                {:else}How could we improve?
                {/if}
            </p>
            <!-- svelte-ignore a11y_autofocus -->
            <textarea
                autofocus
                class="form-control"
                placeholder="Your thoughts..."
                id="q6"
                rows="2"
                bind:value={responses.avis}
            ></textarea>
            <button class="btn btn-success mt-1"> Send! </button>
        {:else if step === 2}
            <p class="fw-bold mb-0">
                Thank you so much for taking the time to share your feedback!
            </p>
        {/if}
    </form>
{/if}
