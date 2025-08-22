// Disable context menu and common view-source/copy shortcuts
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
    if (e.ctrlKey && ['c', 'u', 's'].includes(e.key.toLowerCase())) {
        e.preventDefault();
    }
    if (e.key === 'F12') {
        e.preventDefault();
    }
});