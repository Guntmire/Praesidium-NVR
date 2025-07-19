let users = [];
let editingUserId = null;

async function loadUsers() {
    try {
        const response = await fetch('/api/users');
        users = await response.json();
        renderUsers();
    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('userList').innerHTML = '<div class="empty-state">Error loading users</div>';
    }
}

function renderUsers() {
    const container = document.getElementById('userList');
    if (users.length === 0) {
        container.innerHTML = '<div class="empty-state">No users found</div>';
        return;
    }

    let html = '';
    users.forEach(u => {
        html += `
            <div class='camera-card'>
                <div class='camera-header'>
                    <div class='camera-name'>${u.username}</div>
                    <div class='camera-actions'>
                        <button onclick='editUser("${u.id}")'>Edit</button>
                        <button class='btn-danger' onclick='deleteUser("${u.id}")'>Delete</button>
                    </div>
                </div>
                <div>
                    <strong>Email:</strong> ${u.email}<br>
                    <strong>Active:</strong> ${u.isActive ? 'Yes' : 'No'}
                </div>
            </div>`;
    });

    container.innerHTML = html;
}

function showAddUserModal() {
    editingUserId = null;
    document.getElementById('userModalTitle').textContent = 'Add User';
    document.getElementById('userForm').reset();
    document.getElementById('isActive').checked = true;
    document.getElementById('userModal').style.display = 'block';
}

function editUser(id) {
    const user = users.find(u => u.id === id);
    if (!user) return;
    editingUserId = id;
    document.getElementById('userModalTitle').textContent = 'Edit User';
    document.getElementById('username').value = user.username;
    document.getElementById('password').value = '';
    document.getElementById('email').value = user.email;
    document.getElementById('isActive').checked = user.isActive;
    document.getElementById('userModal').style.display = 'block';
}

function closeUserModal() {
    document.getElementById('userModal').style.display = 'none';
    editingUserId = null;
}

document.getElementById('userForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        email: document.getElementById('email').value,
        isActive: document.getElementById('isActive').checked
    };

    try {
        let response;
        if (editingUserId) {
            response = await fetch(`/api/users/${editingUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
        } else {
            response = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
        }

        if (response.ok) {
            closeUserModal();
            loadUsers();
        } else {
            const err = await response.json();
            alert('Error: ' + err.error);
        }
    } catch (error) {
        console.error('Error saving user:', error);
        alert('Error saving user');
    }
});

async function deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
        const response = await fetch(`/api/users/${id}`, { method: 'DELETE' });
        if (response.ok) {
            loadUsers();
        } else {
            const err = await response.json();
            alert('Error: ' + err.error);
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        alert('Error deleting user');
    }
}

document.getElementById('userModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('userModal')) {
        closeUserModal();
    }
});

document.addEventListener('DOMContentLoaded', loadUsers);
