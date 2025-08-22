document.addEventListener('DOMContentLoaded', () => {
    const aktualizuj = document.getElementById('aktualizuj');
    if (aktualizuj) {
        aktualizuj.addEventListener('click', () => {
            window.location.href = '/static/dashboard.html';
        });
    }

    const infoSection = document.getElementById('info-section');
    const blueSection = document.getElementById('blue-section');
    const leftIcon = document.getElementById('left-icon');
    const rightIcon = document.getElementById('right-icon');
    const leftIconBlue = document.getElementById('left-icon-blue');
    const rightIconBlue = document.getElementById('right-icon-blue');
    const closeIcon = document.getElementById('close-icon');

    let startX;
    if (infoSection) {
        infoSection.addEventListener('touchstart', e => { startX = e.touches[0].clientX; });
        infoSection.addEventListener('touchend', e => {
            const endX = e.changedTouches[0].clientX;
            if (startX > endX + 50) {
                infoSection.style.display = 'none';
                if (blueSection) blueSection.style.display = 'block';
            }
        });
    }

    if (blueSection) {
        blueSection.addEventListener('touchstart', e => { startX = e.touches[0].clientX; });
        blueSection.addEventListener('touchend', e => {
            const endX = e.changedTouches[0].clientX;
            if (startX < endX - 50) {
                blueSection.style.display = 'none';
                if (infoSection) infoSection.style.display = 'block';
            }
        });
    }

    if (rightIcon) {
        rightIcon.addEventListener('click', () => {
            if (infoSection) infoSection.style.display = 'none';
            if (blueSection) blueSection.style.display = 'block';
        });
    }
    if (leftIconBlue) {
        leftIconBlue.addEventListener('click', () => {
            if (blueSection) blueSection.style.display = 'none';
            if (infoSection) infoSection.style.display = 'block';
        });
    }
    if (closeIcon) {
        closeIcon.addEventListener('click', () => {
            if (blueSection) blueSection.style.display = 'none';
        });
    }

    // Shortcuts click handlers
    document.addEventListener('click', e => {
        const t = e.target.closest('.shortcut');
        if (t && t.dataset.href) {
            window.location.href = t.dataset.href;
            return;
        }
        const actionBtn = e.target.closest('[data-action]');
        if (actionBtn) {
            const a = actionBtn.dataset.action;
            if (typeof window[a] === 'function') window[a]();
        }
    });
});