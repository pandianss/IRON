/**
 * Iron Console - Simulation Driver & Router
 */

// --- Routing ---
const views = {
    'Institutional Mirror': 'view-dashboard',
    'Domain I: Execution': 'view-execution',
    'Domain II: Performance': 'view-performance',
    'Domain III: Coordination': 'view-coordination',
    'Domain IV: Risk': 'view-risk',
    'Domain V: Authority': 'view-authority',
    'Domain VI: Intelligence': 'view-intelligence'
};

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();

        // 1. Update Active Link
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        e.target.classList.add('active');

        // 2. Switch View
        const targetViewId = views[e.target.innerText];
        if (targetViewId) {
            document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
            document.getElementById(targetViewId).style.display = 'block';
        }
    });
});

// --- Simulation State ---
const state = {
    streak: 12,
    velocity: 1.8,
    health: 98,
    compliance: 9.4,
    drift: 'NOMINAL'
};

// --- Render Loop ---
function render() {
    // Only update the main dashboard for now (simple sim)
    // In a full app, we'd update all active views
    const dash = document.getElementById('view-dashboard');
    if (dash && dash.style.display !== 'none') {
        dash.querySelector('.card:nth-child(1) .card-value').innerHTML = `${state.streak} <span style="font-size: 0.8rem; color: var(--text-muted);">STREAK</span>`;
        dash.querySelector('.card:nth-child(2) .card-value').innerHTML = `${state.velocity.toFixed(1)} <span style="font-size: 0.8rem; color: var(--text-muted);">ACTIONS/H</span>`;
        dash.querySelector('.card:nth-child(3) .card-value').innerHTML = `${state.health}<span style="font-size: 1.2rem;">%</span>`;
    }
}

// Tick
setInterval(() => {
    // Randomize Velocity
    state.velocity += (Math.random() - 0.5) * 0.2;
    if (state.velocity < 0) state.velocity = 0;

    // Rare event: Drift Warning
    if (Math.random() < 0.05) {
        state.drift = 'WARNING';
        const el = document.querySelector('#view-dashboard .card:nth-child(6) .card-value');
        if (el) {
            el.innerText = state.drift;
            el.style.color = '#eab308';
        }
    } else if (Math.random() < 0.1) {
        state.drift = 'NOMINAL';
        const el = document.querySelector('#view-dashboard .card:nth-child(6) .card-value');
        if (el) {
            el.innerText = state.drift;
            el.style.color = 'var(--accent-cyan)';
        }
    }

    render();
}, 2000);

console.log("Iron Console: Router & Simulation Active");
