package web

import "embed"

//go:embed templates/*
var StaticFS embed.FS

const LoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuthProxy • Login</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --border: #334155;
            --error-bg: #450a0a;
            --error-text: #fca5a5;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1.5rem; }
        .login-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 2.5rem; width: 100%; max-width: 420px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
        .logo { text-align: center; margin-bottom: 2rem; }
        .logo h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; color: #fff; }
        .logo p { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }
        .google-btn { display: flex; align-items: center; justify-content: center; gap: 0.75rem; width: 100%; padding: 0.75rem; background: #ffffff; color: #000000; font-weight: 600; border-radius: 6px; text-decoration: none; font-size: 0.95rem; transition: background 0.2s; margin-bottom: 1.5rem; }
        .google-btn:hover { background: #f1f5f9; }
        .divider { display: flex; align-items: center; text-align: center; margin: 1.5rem 0; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid var(--border); }
        .divider span { padding: 0 0.75rem; }
        .form-group { margin-bottom: 1.25rem; }
        .form-group label { display: block; font-size: 0.875rem; color: var(--text-muted); margin-bottom: 0.5rem; font-weight: 500; }
        .form-group input { width: 100%; padding: 0.75rem; background: #0f172a; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-size: 0.95rem; outline: none; transition: border-color 0.2s; }
        .form-group input:focus { border-color: var(--primary); }
        .submit-btn { width: 100%; padding: 0.75rem; background: var(--primary); color: #fff; font-weight: 600; border: none; border-radius: 6px; font-size: 0.95rem; cursor: pointer; transition: background 0.2s; }
        .submit-btn:hover { background: var(--primary-hover); }
        .error-box { background: var(--error-bg); border: 1px solid #7f1d1d; color: var(--error-text); padding: 0.75rem; border-radius: 6px; font-size: 0.875rem; margin-bottom: 1.5rem; display: none; }
        .footer { text-align: center; margin-top: 2rem; color: var(--text-muted); font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <h1>OAuthProxy</h1>
            <p>MCP OAuth Proxy Identity Server</p>
        </div>

        <div id="error-box" class="error-box"></div>

        <a href="/auth/google/login?state={{.State}}" class="google-btn">
            <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.27v3.15C3.25 21.3 7.31 24 12 24z"/><path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.27C.46 8.2 0 10.04 0 12s.46 3.8 1.27 5.42l4.01-3.15z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.25 2.7 1.27 6.58l4.01 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/></svg>
            Sign in with Google Workspace
        </a>
        <div class="divider"><span>OR</span></div>

        <form method="POST" action="/oauth/v2/login">
            <input type="hidden" name="authRequestID" value="{{.AuthRequestID}}">
            <input type="hidden" name="state" value="{{.State}}">

            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="admin or name@mirrormedia.mg" required autocomplete="username">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
            </div>

            <button type="submit" class="submit-btn">Sign In</button>
        </form>

        <div class="footer">
            Powered by OAuthProxy • GCP Cloud Run
        </div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const err = urlParams.get('error');
        if (err) {
            const errBox = document.getElementById('error-box');
            errBox.innerText = decodeURIComponent(err);
            errBox.style.display = 'block';
        }
    </script>
</body>
</html>`

const ConsoleHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuthProxy • User Console</title>
    <style>
        :root {
            --bg-color: #0b1329;
            --sidebar-bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --border: #334155;
            --success: #22c55e;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background: var(--sidebar-bg); border-right: 1px solid var(--border); padding: 1.5rem; flex-shrink: 0; }
        .sidebar-title { font-size: 1.25rem; font-weight: 700; color: #fff; margin-bottom: 2rem; display: flex; align-items: center; gap: 0.5rem; }
        .nav-item { display: block; padding: 0.75rem 1rem; color: var(--text-muted); text-decoration: none; border-radius: 6px; font-weight: 500; margin-bottom: 0.5rem; cursor: pointer; transition: all 0.2s; }
        .nav-item:hover, .nav-item.active { background: #1e293b; color: #fff; }
        .content { flex: 1; padding: 2.5rem; overflow-y: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        .header h2 { font-size: 1.5rem; font-weight: 600; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
        .table { width: 100%; border-collapse: collapse; text-align: left; }
        .table th, .table td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        .table th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        .btn { padding: 0.5rem 1rem; background: var(--primary); color: #fff; border: none; border-radius: 6px; font-size: 0.875rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 0.5rem; }
        .btn-danger { background: var(--danger); }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
        .badge-success { background: #064e3b; color: #6ee7b7; }
        .badge-info { background: #1e3a8a; color: #93c5fd; }
        .badge-user { background: #374151; color: #d1d5db; }
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.35rem; }
        .form-group input { width: 100%; padding: 0.5rem 0.75rem; background: #0f172a; border: 1px solid var(--border); border-radius: 6px; color: #fff; }
        .profile-box { display: flex; align-items: center; gap: 1.5rem; }
        .profile-avatar { width: 64px; height: 64px; border-radius: 50%; background: #3b82f6; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; font-weight: 700; color: #fff; }
        .profile-details p { color: var(--text-muted); margin-top: 0.25rem; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-title">
            <span>⚡ OAuthProxy</span>
        </div>
        <a id="nav-profile" class="nav-item active" onclick="showTab('profile')">My Profile</a>
        <a id="nav-clients" class="nav-item admin-only" style="display:none;" onclick="showTab('clients')">OAuth Applications</a>
        <a id="nav-users" class="nav-item admin-only" style="display:none;" onclick="showTab('users')">User Management</a>
        <a id="nav-system" class="nav-item admin-only" style="display:none;" onclick="showTab('system')">System & Metadata</a>
    </div>

    <div class="content">
        <div class="header">
            <h2 id="page-title">User Account Profile</h2>
            <div>
                <a href="/.well-known/openid-configuration" target="_blank" class="btn">OIDC Metadata ↗</a>
            </div>
        </div>

        <!-- TAB: MY PROFILE (USER SELF SERVICE) -->
        <div id="tab-profile">
            <div class="card">
                <div class="profile-box">
                    <div id="profile-avatar-container" class="profile-avatar">?</div>
                    <div class="profile-details">
                        <h3 id="profile-name">Loading Profile...</h3>
                        <p id="profile-email">-</p>
                        <p id="profile-role" style="margin-top: 0.5rem;"><span class="badge badge-info">Standard User</span></p>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 0.5rem;">Single Sign-On Status</h3>
                <p style="color: var(--text-muted); font-size: 0.9rem; line-height: 1.5;">
                    You are authenticated via <strong>OAuthProxy Identity Provider</strong>.<br>
                    Your account is authorized to access integrated company applications (e.g. CMS, GA MCP Agent) using Google Workspace SSO.
                </p>
            </div>
        </div>

        <!-- TAB: CLIENTS (ADMIN ONLY) -->
        <div id="tab-clients" style="display: none;">
            <div class="card">
                <h3 style="margin-bottom: 1rem;">Create OAuth Application</h3>
                <form id="create-client-form">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Client Name</label>
                            <input type="text" id="client-name" placeholder="Web Portal" required>
                        </div>
                        <div class="form-group">
                            <label>Redirect URIs (comma separated)</label>
                            <input type="text" id="client-uris" placeholder="https://app.example.com/callback" required>
                        </div>
                    </div>
                    <button type="submit" class="btn">Create Application</button>
                </form>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 1rem;">Registered OAuth Clients</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Client ID</th>
                            <th>Client Secret</th>
                            <th>Redirect URIs</th>
                            <th>Trusted</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="clients-tbody">
                        <tr><td colspan="6">Loading clients...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB: USERS (ADMIN ONLY) -->
        <div id="tab-users" style="display: none;">
            <div class="card">
                <h3 style="margin-bottom: 1rem;">Add User (Admin Managed)</h3>
                <form id="create-user-form">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" id="user-username" placeholder="johndoe" required>
                        </div>
                        <div class="form-group">
                            <label>Email Address</label>
                            <input type="email" id="user-email" placeholder="john@mirrormedia.mg" required>
                        </div>
                        <div class="form-group">
                            <label>Full Name</label>
                            <input type="text" id="user-fullname" placeholder="John Doe" required>
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" id="user-password" placeholder="••••••••" required>
                        </div>
                    </div>
                    <button type="submit" class="btn">Add User</button>
                </form>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 1rem;">Authorized Users</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Full Name</th>
                            <th>Provider</th>
                            <th>Role</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="users-tbody">
                        <tr><td colspan="6">Loading users...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB: SYSTEM (ADMIN ONLY) -->
        <div id="tab-system" style="display: none;">
            <div class="card">
                <h3 style="margin-bottom: 1rem;">System Status & Configuration</h3>
                <p style="color: var(--text-muted); margin-bottom: 1rem;">OAuth Proxy Active Instance</p>
                <div id="system-info">Loading system metadata...</div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = null;

        async function init() {
            try {
                const res = await fetch('/api/v1/me');
                if (!res.ok) {
                    window.location.href = '/ui/console/';
                    return;
                }
                currentUser = await res.json();
                renderProfile();

                if (currentUser && currentUser.is_admin) {
                    document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'block');
                    document.title = 'OAuthProxy • Management Console';
                } else {
                    document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
                    document.title = 'OAuthProxy • User Portal';
                }
            } catch(e) {
                console.error(e);
            }
        }

        function renderProfile() {
            if (!currentUser) return;
            document.getElementById('profile-name').innerText = currentUser.full_name || currentUser.username;
            document.getElementById('profile-email').innerText = currentUser.email || '-';

            const avatarContainer = document.getElementById('profile-avatar-container');
            if (currentUser.avatar_url) {
                avatarContainer.innerHTML = '<img src="' + currentUser.avatar_url + '" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">';
            } else {
                avatarContainer.innerText = (currentUser.username || 'U').substring(0, 1).toUpperCase();
            }

            const roleContainer = document.getElementById('profile-role');
            if (currentUser.is_admin) {
                roleContainer.innerHTML = '<span class="badge badge-success">System Administrator</span>';
            } else {
                roleContainer.innerHTML = '<span class="badge badge-info">Standard User (' + currentUser.provider + ')</span>';
            }
        }

        function showTab(tab) {
            document.getElementById('tab-profile').style.display = tab === 'profile' ? 'block' : 'none';
            document.getElementById('tab-clients').style.display = tab === 'clients' ? 'block' : 'none';
            document.getElementById('tab-users').style.display = tab === 'users' ? 'block' : 'none';
            document.getElementById('tab-system').style.display = tab === 'system' ? 'block' : 'none';
            
            document.querySelectorAll('.nav-item').forEach(function(el) { el.classList.remove('active'); });
            const activeNav = document.getElementById('nav-' + tab);
            if (activeNav) activeNav.classList.add('active');

            const pageTitle = document.getElementById('page-title');
            if (tab === 'profile') pageTitle.innerText = 'User Account Profile';
            if (tab === 'clients') { pageTitle.innerText = 'OAuth Applications'; loadClients(); }
            if (tab === 'users') { pageTitle.innerText = 'User Management'; loadUsers(); }
            if (tab === 'system') { pageTitle.innerText = 'System Status'; loadSystem(); }
        }

        async function loadClients() {
            const res = await fetch('/api/v1/clients');
            if (!res.ok) return;
            const data = await res.json();
            const tbody = document.getElementById('clients-tbody');
            tbody.innerHTML = '';

            if (!data || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6">No registered clients found.</td></tr>';
                return;
            }

            data.forEach(function(c) {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td><strong>' + c.name + '</strong></td>' +
                    '<td><code>' + c.id + '</code></td>' +
                    '<td><code>' + c.secret + '</code></td>' +
                    '<td>' + (c.redirect_uris || []).join('<br>') + '</td>' +
                    '<td><span class="badge badge-success">' + (c.is_trusted ? 'Trusted' : 'Standard') + '</span></td>' +
                    '<td><button class="btn btn-danger btn-sm" onclick="deleteClient(\'' + c.id + '\')">Delete</button></td>';
                tbody.appendChild(tr);
            });
        }

        async function loadUsers() {
            const res = await fetch('/api/v1/users');
            if (!res.ok) return;
            const data = await res.json();
            const tbody = document.getElementById('users-tbody');
            tbody.innerHTML = '';

            if (!data || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6">No users found.</td></tr>';
                return;
            }

            data.forEach(function(u) {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td><strong>' + u.username + '</strong></td>' +
                    '<td>' + u.email + '</td>' +
                    '<td>' + (u.full_name || '-') + '</td>' +
                    '<td><span class="badge badge-info">' + u.provider + '</span></td>' +
                    '<td>' + (u.is_admin ? '<span class="badge badge-success">Admin</span>' : 'User') + '</td>' +
                    '<td>' + (u.is_admin ? '-' : '<button class="btn btn-danger btn-sm" onclick="deleteUser(\'' + u.id + '\')">Delete</button>') + '</td>';
                tbody.appendChild(tr);
            });
        }

        async function loadSystem() {
            const res = await fetch('/.well-known/openid-configuration');
            const data = await res.json();
            document.getElementById('system-info').innerHTML = '<pre style="background: #0f172a; padding: 1rem; border-radius: 6px; overflow-x: auto;">' + JSON.stringify(data, null, 2) + '</pre>';
        }

        document.getElementById('create-client-form').onsubmit = async function(e) {
            e.preventDefault();
            const name = document.getElementById('client-name').value;
            const uris = document.getElementById('client-uris').value;
            await fetch('/api/v1/clients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, redirect_uris: uris.split(',') })
            });
            document.getElementById('client-name').value = '';
            document.getElementById('client-uris').value = '';
            loadClients();
        };

        document.getElementById('create-user-form').onsubmit = async function(e) {
            e.preventDefault();
            const username = document.getElementById('user-username').value;
            const email = document.getElementById('user-email').value;
            const full_name = document.getElementById('user-fullname').value;
            const password = document.getElementById('user-password').value;

            await fetch('/api/v1/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, email: email, full_name: full_name, password: password })
            });
            document.getElementById('user-username').value = '';
            document.getElementById('user-email').value = '';
            document.getElementById('user-fullname').value = '';
            document.getElementById('user-password').value = '';
            loadUsers();
        };

        async function deleteClient(id) {
            if (confirm('Delete client application?')) {
                await fetch('/api/v1/clients/' + id, { method: 'DELETE' });
                loadClients();
            }
        }

        async function deleteUser(id) {
            if (confirm('Delete user account?')) {
                await fetch('/api/v1/users/' + id, { method: 'DELETE' });
                loadUsers();
            }
        }

        init();
    </script>
</body>
</html>`
