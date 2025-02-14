document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.fromEntries(formData))
            });
            if (response.ok) {
                const { token } = await response.json();
                localStorage.setItem('token', token);
                window.location.href = 'market.html';
            } else {
                document.getElementById('message').innerText = 'Login failed. Please try again.';
            }
        });
    }

    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.href = 'index.html';
        });
    }

    if (window.location.pathname.includes('market.html')) {
        loadMarket();
    }
});

async function loadMarket() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    const response = await fetch('/api/market', { headers: { 'Authorization': `Bearer ${token}` } });
    if (response.ok) {
        const artifacts = await response.json();
        const artifactsDiv = document.getElementById('artifacts');
        artifactsDiv.innerHTML = ''; 
        artifacts.forEach(artifact => {
            const div = document.createElement('div');
            div.className = 'artifact';
            div.innerHTML = `<h3>${artifact.name}</h3><p>${artifact.description}</p>`;
            artifactsDiv.appendChild(div);
        });
    } else {
        alert('Access denied');
        window.location.href = 'index.html';
    }
}
