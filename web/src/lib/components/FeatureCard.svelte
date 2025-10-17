<script lang="ts">
    interface Props {
        icon: string;
        title: string;
        description: string;
        variant?: "primary" | "success" | "warning" | "danger" | "info" | "secondary";
    }

    let { icon, title, description, variant = "primary" }: Props = $props();
</script>

<div class="card h-100 text-center p-4">
    <div class="feature-icon bg-{variant} bg-opacity-10 text-{variant} mx-auto">
        <i class="bi {icon}"></i>
    </div>
    <h5 class="fw-bold">{title}</h5>
    <p class="text-muted small mb-0">
        {description}
    </p>
</div>

<style>
    .feature-icon {
        width: 4rem;
        height: 4rem;
        border-radius: 0.75rem;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
</style>
