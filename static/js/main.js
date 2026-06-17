// Secure Cloud Data Vault — Frontend Module
// Handles animations, particles, AJAX forms, crypto sandbox, dashboard logs, and charts.

document.addEventListener('DOMContentLoaded', function () {

    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

    // ── Particle Background ──
    initParticles();

    // ── Navbar Scroll Effect ──
    const navbar = document.getElementById('vault-navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 20);
        }, { passive: true });
    }

    // ── Fade-in on Scroll ──
    const fadeEls = document.querySelectorAll('.fade-in');
    if (fadeEls.length) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
        fadeEls.forEach(el => observer.observe(el));
    }

    // ── Animated Counters ──
    const counters = document.querySelectorAll('.counter');
    if (counters.length) {
        const counterObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounter(entry.target);
                    counterObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });
        counters.forEach(c => counterObserver.observe(c));
    }

    // ── Mouse Parallax ──
    const parallaxEls = document.querySelectorAll('[data-parallax]');
    if (parallaxEls.length) {
        document.addEventListener('mousemove', (e) => {
            const cx = (e.clientX / window.innerWidth - 0.5) * 2;
            const cy = (e.clientY / window.innerHeight - 0.5) * 2;
            parallaxEls.forEach(el => {
                const factor = parseFloat(el.dataset.parallax) || 0.02;
                el.style.transform = `translate(${cx * factor * 40}px, ${cy * factor * 40}px)`;
            });
        }, { passive: true });
    }

    // ── Password Visibility Toggle ──
    document.querySelectorAll('.password-toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (!input) return;
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            const icon = btn.querySelector('i');
            icon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
        });
    });

    // ── Password Strength Checker ──
    const passwordInput = document.getElementById('reg-password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function () {
            const val = this.value;
            let score = 0;
            const feedback = [];

            if (val.length >= 8) score += 20; else feedback.push('Min 8 chars');
            if (/[A-Z]/.test(val)) score += 20; else feedback.push('Need Uppercase');
            if (/[a-z]/.test(val)) score += 20; else feedback.push('Need Lowercase');
            if (/\d/.test(val)) score += 20; else feedback.push('Need Number');
            if (/[!@#$%^&*(),.?":{}|<>]/.test(val)) score += 20; else feedback.push('Need Special Char');

            const bar = document.getElementById('password-strength-bar');
            const txt = document.getElementById('password-strength-text');
            if (!bar || !txt) return;

            bar.style.width = score + '%';
            if (score < 40) {
                bar.style.background = '#EF4444';
                bar.style.color = '#EF4444';
                txt.innerHTML = 'Weak: ' + feedback.join(', ');
                txt.style.color = '#FCA5A5';
            } else if (score < 80) {
                bar.style.background = '#F59E0B';
                bar.style.color = '#F59E0B';
                txt.innerHTML = 'Moderate: ' + feedback.join(', ');
                txt.style.color = '#FCD34D';
            } else {
                bar.style.background = '#22C55E';
                bar.style.color = '#22C55E';
                txt.innerHTML = '<i class="fa-solid fa-circle-check"></i> Strong Password';
                txt.style.color = '#86EFAC';
            }
        });
    }

    // ── AJAX Register ──
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = new FormData(this);
            const alertBox = document.getElementById('register-alert');
            const submitBtn = this.querySelector('button[type="submit"]');

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Securing Account...';
            alertBox.className = 'd-none';

            fetch('/api/register', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
                body: formData
            })
            .then(res => res.json().then(data => ({ status: res.status, body: data })))
            .then(result => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved me-2"></i> Register Secured Account';

                if (result.status === 201) {
                    alertBox.className = 'alert alert-success';
                    alertBox.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> ' + result.body.message + ' Redirecting to Login...';
                    setTimeout(() => { window.location.href = '/login'; }, 2000);
                } else {
                    alertBox.className = 'alert alert-danger';
                    alertBox.innerHTML = result.body.message || 'Registration failed.';
                }
            })
            .catch(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved me-2"></i> Register Secured Account';
                alertBox.className = 'alert alert-danger';
                alertBox.innerHTML = 'An unexpected connection error occurred.';
            });
        });
    }

    // ── AJAX Login ──
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const formData = new FormData(this);
            const alertBox = document.getElementById('login-alert');
            const submitBtn = this.querySelector('button[type="submit"]');

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Authenticating...';
            alertBox.className = 'd-none';

            fetch('/api/login', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
                body: formData
            })
            .then(res => res.json().then(data => ({ status: res.status, body: data })))
            .then(result => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved me-2"></i> Login Securely';

                if (result.status === 200) {
                    alertBox.className = 'alert alert-success';
                    alertBox.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> Authentication Successful! Establishing Secure Session...';
                    setTimeout(() => { window.location.href = '/profile'; }, 1500);
                } else {
                    alertBox.className = 'alert alert-danger';
                    alertBox.innerHTML = result.body.message || 'Login failed.';
                }
            })
            .catch(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved me-2"></i> Login Securely';
                alertBox.className = 'alert alert-danger';
                alertBox.innerHTML = 'An unexpected connection error occurred.';
            });
        });
    }

    // ── Crypto Sandbox ──
    const btnEncrypt = document.getElementById('btn-test-encrypt');
    const btnDecrypt = document.getElementById('btn-test-decrypt');

    async function parseApiResponse(res) {
        const contentType = res.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.message || `Request failed (${res.status})`);
            }
            return data;
        }
        if (res.status === 401) throw new Error('Session expired. Please refresh the page and login again.');
        if (res.status === 403) throw new Error('Access Denied: You require ADMIN_ACCESS capability to decrypt values.');
        throw new Error(`Server returned an unexpected response (${res.status}). Please refresh and try again.`);
    }

    if (btnEncrypt) {
        btnEncrypt.addEventListener('click', async function () {
            const rawText = document.getElementById('test-raw-text').value;
            const outputField = document.getElementById('test-encrypted-result');
            if (!rawText.trim()) { alert('Please enter some text to encrypt.'); return; }
            outputField.value = 'Encrypting...';
            btnEncrypt.disabled = true;

            try {
                const res = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ plain_text: rawText })
                });
                const data = await parseApiResponse(res);
                outputField.value = data.status === 'Success' ? data.encrypted : 'Error: ' + data.message;
            } catch (err) {
                outputField.value = err.message || 'Connection error.';
            } finally {
                btnEncrypt.disabled = false;
            }
        });
    }

    if (btnDecrypt) {
        btnDecrypt.addEventListener('click', async function () {
            const cipherText = document.getElementById('test-cipher-text').value;
            const outputField = document.getElementById('test-decrypted-result');
            if (!cipherText.trim()) { alert('Please enter a Base64 AES-256 ciphertext.'); return; }
            outputField.value = 'Decrypting & verifying tag...';
            btnDecrypt.disabled = true;

            try {
                const res = await fetch('/api/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ cipher_text: cipherText })
                });
                const data = await parseApiResponse(res);
                outputField.value = data.status === 'Success' ? data.decrypted : 'Error: ' + data.message;
            } catch (err) {
                outputField.value = err.message || 'Failed to decrypt.';
            } finally {
                btnDecrypt.disabled = false;
            }
        });
    }

    // ── Attack Logs: Search, Filter, Sort ──
    const searchInput = document.getElementById('log-search');
    const typeFilter = document.getElementById('log-type-filter');
    const tableBody = document.getElementById('log-table-body');
    let sortCol = null;
    let sortDir = 'asc';

    if (tableBody && (searchInput || typeFilter)) {
        function renderLogRows(logs) {
            if (logs.length > 0) {
                let html = '';
                logs.forEach(log => {
                    html += `
                        <tr class="terminal-tr-blocked"
                            data-id="${log.id}"
                            data-type="${escapeAttr(log.attack_type)}"
                            data-input="${escapeAttr(log.input_data)}"
                            data-ip="${escapeAttr(log.ip_address)}"
                            data-status="Blocked"
                            data-timestamp="${log.timestamp}">
                            <td class="fw-bold" style="color: var(--text-primary);">#${log.id}</td>
                            <td><span class="badge-cyber-danger">${escapeHtml(log.attack_type)}</span></td>
                            <td style="color: #FCD34D;" class="text-break">${escapeHtml(log.input_data)}</td>
                            <td style="color: var(--accent-secondary);">${escapeHtml(log.ip_address)}</td>
                            <td><span class="badge-cyber-danger" style="background: rgba(239,68,68,0.25); color: #FCA5A5;">Blocked</span></td>
                            <td class="text-muted-custom small">${escapeHtml(log.timestamp)}</td>
                        </tr>`;
                });
                tableBody.innerHTML = html;
            } else {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-muted-custom">No security incident logs matching the filter.</td></tr>';
            }
        }

        function updateAttackLogs() {
            const search = searchInput ? searchInput.value : '';
            const type = typeFilter ? typeFilter.value : '';

            tableBody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-muted-custom"><span class="spinner-border spinner-border-sm"></span> Loading logs...</td></tr>';

            fetch(`/api/attack_logs?search=${encodeURIComponent(search)}&type=${encodeURIComponent(type)}`)
            .then(res => {
                if (res.status === 403) throw new Error('Access Denied: Missing VIEW_LOGS capability.');
                return res.json();
            })
            .then(data => {
                if (data.status === 'Success') {
                    renderLogRows(data.logs);
                } else {
                    tableBody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-muted-custom">No security incident logs matching the filter.</td></tr>';
                }
            })
            .catch(err => {
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4" style="color: var(--danger);">${err.message || 'Error fetching attack logs.'}</td></tr>`;
            });
        }

        let debounceTimer;
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(updateAttackLogs, 300);
            });
        }
        if (typeFilter) typeFilter.addEventListener('change', updateAttackLogs);

        // Client-side sort on server-rendered rows
        const table = document.getElementById('attack-logs-table');
        if (table) {
            table.querySelectorAll('th[data-sort]').forEach(th => {
                th.addEventListener('click', () => {
                    const col = th.dataset.sort;
                    if (sortCol === col) {
                        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                    } else {
                        sortCol = col;
                        sortDir = 'asc';
                    }

                    table.querySelectorAll('th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
                    th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');

                    const rows = Array.from(tableBody.querySelectorAll('tr[data-id]'));
                    const keyMap = { id: 'id', type: 'type', input: 'input', ip: 'ip', status: 'status', timestamp: 'timestamp' };
                    const key = keyMap[col];

                    rows.sort((a, b) => {
                        let va = a.dataset[key] || '';
                        let vb = b.dataset[key] || '';
                        if (col === 'id') { va = parseInt(va); vb = parseInt(vb); }
                        if (va < vb) return sortDir === 'asc' ? -1 : 1;
                        if (va > vb) return sortDir === 'asc' ? 1 : -1;
                        return 0;
                    });

                    rows.forEach(row => tableBody.appendChild(row));
                });
            });
        }
    }

    // ── Chart.js Dashboard ──
    const chartCanvas = document.getElementById('attackChart');
    if (chartCanvas) {
        fetch('/api/attack_logs')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'Success') {
                const stats = {};
                data.logs.forEach(log => {
                    stats[log.attack_type] = (stats[log.attack_type] || 0) + 1;
                });

                const labels = Object.keys(stats);
                const values = Object.values(stats);
                const finalLabels = labels.length > 0 ? labels : ['SQLi Signature', 'Trivial OR Condition', 'UNION SELECT', 'DROP TABLE Attempt'];
                const finalValues = values.length > 0 ? values : [0, 0, 0, 0];

                new Chart(chartCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: finalLabels,
                        datasets: [{
                            data: finalValues,
                            backgroundColor: ['#A855F7', '#D946EF', '#C084FC', '#EF4444', '#22C55E', '#F59E0B'],
                            borderColor: 'rgba(18, 18, 30, 0.85)',
                            borderWidth: 2,
                            hoverOffset: 8
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: { animateRotate: true, duration: 1200 },
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    color: '#D1D5DB',
                                    font: { family: 'Inter', size: 11 },
                                    padding: 12,
                                    usePointStyle: true
                                }
                            }
                        }
                    }
                });
            }
        })
        .catch(err => console.error('Could not build dashboard charts:', err));
    }

    // ── Helpers ──
    function animateCounter(el) {
        const target = parseInt(el.dataset.target, 10) || 0;
        const duration = 1500;
        const start = performance.now();

        function step(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.floor(eased * target);
            if (progress < 1) requestAnimationFrame(step);
            else el.textContent = target;
        }
        requestAnimationFrame(step);
    }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, s => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[s]);
    }

    function escapeAttr(str) {
        return escapeHtml(str).replace(/"/g, '&quot;');
    }

    function initParticles() {
        const canvas = document.getElementById('particle-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        let particles = [];
        let animId;
        const PARTICLE_COUNT = window.innerWidth < 768 ? 40 : 80;

        function resize() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }

        function createParticles() {
            particles = [];
            for (let i = 0; i < PARTICLE_COUNT; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    r: Math.random() * 1.5 + 0.5,
                    dx: (Math.random() - 0.5) * 0.3,
                    dy: (Math.random() - 0.5) * 0.3,
                    alpha: Math.random() * 0.5 + 0.2
                });
            }
        }

        function draw() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            particles.forEach((p, i) => {
                p.x += p.dx;
                p.y += p.dy;
                if (p.x < 0) p.x = canvas.width;
                if (p.x > canvas.width) p.x = 0;
                if (p.y < 0) p.y = canvas.height;
                if (p.y > canvas.height) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(168, 85, 247, ${p.alpha})`;
                ctx.fill();

                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                    if (dist < 120) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.strokeStyle = `rgba(168, 85, 247, ${0.08 * (1 - dist / 120)})`;
                        ctx.stroke();
                    }
                }
            });

            animId = requestAnimationFrame(draw);
        }

        resize();
        createParticles();
        draw();

        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                resize();
                createParticles();
            }, 200);
        }, { passive: true });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                cancelAnimationFrame(animId);
            } else {
                draw();
            }
        });
    }
});
