<!--
     The branded loader: the logo mark itself, its five tiles lighting up one
     after the other, tracing a loop around the mark. Same loader as
     HappyDomain's, in HappyDeliver purple.
-->

<script lang="ts">
    interface Props {
        /** Accessible name; defaults to the generic waiting message. */
        label?: string;
        /** CSS width of the drawing; its height follows. */
        width?: string;
        class?: string;
    }

    let { label = "Loading…", width = "4rem", class: className = "" }: Props = $props();

    // The five tiles of the mark, as offsets in the viewBox; the order they
    // light up in is drawn by schedule().
    const TILES: [number, number][] = [
        [0, 116.73],
        [232.91, 0],
        [0, 0],
        [232.91, 116.73],
        [116.478, 58.3945],
    ];

    // The tour is a long run of rounds: in each round every tile lights up
    // exactly once, in a freshly shuffled order, so the share between tiles is
    // even while the sequence takes a while to come back around.
    const ROUNDS = 6;
    const SLOT = 400; // ms between two consecutive flashes
    const PULSE = [0, 120, 400]; // ms: rest, peak, back to rest; done before the next flash starts

    function shuffled(): number[] {
        const a = TILES.map((_, i) => i);
        for (let i = a.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
    }

    // Flash order over the whole run. A tile never follows itself directly,
    // wrap-around included, so a flash always has ended before its tile's next.
    function schedule(): number[] {
        const order: number[] = [];
        for (let r = 0; r < ROUNDS; r++) {
            let round: number[];
            do {
                round = shuffled();
            } while (order.length > 0 && round[0] === order[order.length - 1]);
            order.push(...round);
        }
        if (order[0] === order[order.length - 1]) {
            [order[0], order[1]] = [order[1], order[0]];
        }
        return order;
    }

    let rects: SVGRectElement[] = $state([]);

    $effect(() => {
        const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const slot = reduced ? SLOT * 2 : SLOT;
        const scale = reduced ? 2 : 1;
        const order = schedule();
        const total = order.length * slot;

        const animations = TILES.map((_, tile) => {
            const starts = order.flatMap((t, k) => (t === tile ? [k * slot] : []));
            const first = starts[0];
            const rest = {
                fill: "var(--tile-rest)",
                ...(reduced ? {} : { transform: "scale(var(--rest))" }),
            };
            const peak = {
                fill: "var(--tile-peak)",
                ...(reduced ? {} : { transform: "scale(var(--peak))" }),
            };
            const frames: Keyframe[] = [];
            for (const start of starts) {
                const at = start - first;
                frames.push(
                    { offset: at / total, ...rest, easing: "cubic-bezier(0.34, 1.56, 0.64, 1)" },
                    {
                        offset: (at + PULSE[1] * scale) / total,
                        ...peak,
                        easing: "cubic-bezier(0.4, 0, 0.6, 1)",
                    },
                    { offset: (at + PULSE[2] * scale) / total, ...rest },
                );
            }
            frames.push({ offset: 1, ...rest });
            // Shifted so the tile's first flash opens its timeline.
            return rects[tile]?.animate(frames, {
                duration: total,
                delay: first,
                iterations: Infinity,
            });
        });

        return () => animations.forEach((a) => a?.cancel());
    });
</script>

<svg
    class="tile-loader {className}"
    viewBox="0 0 335.675 219.718"
    style:width
    role="status"
    aria-label={label}
>
    {#each TILES as [x, y], i (i)}
        <rect
            bind:this={rects[i]}
            {x}
            {y}
            width="102.765"
            height="102.988"
            rx="38.2391"
            ry="38.3217"
        />
    {/each}
</svg>

<style>
    .tile-loader {
        /* The mark barely breathes: it rests at its true size and peaks just
           over it, the colour carrying most of the signal. Tiles sit 13.7
           units apart, and a peak of 1.1 eats 5.1 units on each side, so even
           two neighbours at full swell stay clear of one another. */
        --rest: 1;
        --peak: 1.1;
        /* Tiles rest on a pale purple and flash to the brand purple. */
        --tile-rest: var(--hd-purple-200);
        --tile-peak: var(--hd-purple-500);
        display: inline-block;
        max-width: 80vw;
        height: auto;
        vertical-align: middle;
        /* Tiles at full swell overhang the viewBox on its left and top. */
        overflow: visible;
    }

    /* On the dark canvas the pale purple glares: rest on a deep purple instead
       (purple-800, the dark theme's accent border), so only the lit tile
       stands out. */
    :global([data-bs-theme="dark"]) .tile-loader {
        --tile-rest: var(--hd-purple-800);
    }

    rect {
        fill: var(--tile-rest);
        transform-box: fill-box;
        transform-origin: center;
        transform: scale(var(--rest));
    }
</style>
