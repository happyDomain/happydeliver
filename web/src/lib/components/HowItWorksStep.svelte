<script lang="ts">
    interface Props {
        step: number;
        title: string;
        description: string;
    }

    let { step, title, description }: Props = $props();
</script>

<div class="card h-100 text-center p-4">
    <div class="display-1 text-primary fw-bold opacity-25">{step}</div>
    <h5 class="fw-bold mt-3">{title}</h5>
    <p class="text-muted mb-0">
        {description}
    </p>
</div>
