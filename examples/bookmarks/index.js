
const APP_ID = 'bookmarks';
let bookmarks = [];
let editingId = null;

// Show error message
function showError(message) {
  const errorEl = document.getElementById('error');
  errorEl.textContent = message;
  errorEl.classList.add('show');
  setTimeout(() => errorEl.classList.remove('show'), 5000);
}

// Toggle form visibility
function toggleForm() {
  const form = document.getElementById('addForm');
  form.classList.toggle('show');
  if (form.classList.contains('show')) {
    document.getElementById('titleInput').focus();
  }
}

// Cancel form
function cancelForm() {
  document.getElementById('addForm').classList.remove('show');
  clearForm();
}

// Clear form
function clearForm() {
  document.getElementById('titleInput').value = '';
  document.getElementById('urlInput').value = '';
  document.getElementById('categoryInput').value = '';
  document.getElementById('descriptionInput').value = '';
  editingId = null;
}

// Load bookmarks from Fleabox API
async function loadBookmarks() {
  try {
    const response = await fetch(`/api/${APP_ID}/data/bookmarks.json`);
    if (response.ok) {
      bookmarks = await response.json();
    } else if (response.status === 404) {
      bookmarks = [];
    } else {
      throw new Error('Failed to load bookmarks');
    }
    renderBookmarks();
  } catch (error) {
    showError('Error loading bookmarks: ' + error.message);
  }
}

// Save bookmarks to Fleabox API
async function saveBookmarks() {
  try {
    const response = await fetch(`/api/${APP_ID}/data/bookmarks.json`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(bookmarks)
    });

    if (!response.ok) {
      throw new Error('Failed to save bookmarks');
    }
  } catch (error) {
    showError('Error saving bookmarks: ' + error.message);
  }
}

// Save bookmark (create or update)
async function saveBookmark() {
  const title = document.getElementById('titleInput').value.trim();
  const url = document.getElementById('urlInput').value.trim();
  const category = document.getElementById('categoryInput').value.trim() || 'Uncategorized';
  const description = document.getElementById('descriptionInput').value.trim();

  if (!title || !url) {
    showError('Please enter both title and URL');
    return;
  }

  // Simple URL validation
  try {
    new URL(url);
  } catch {
    showError('Please enter a valid URL');
    return;
  }

  if (editingId) {
    // Update existing bookmark
    const bookmark = bookmarks.find(b => b.id === editingId);
    if (bookmark) {
      bookmark.title = title;
      bookmark.url = url;
      bookmark.category = category;
      bookmark.description = description;
      bookmark.updatedAt = new Date().toISOString();
    }
  } else {
    // Create new bookmark
    const bookmark = {
      id: Date.now(),
      title,
      url,
      category,
      description,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    bookmarks.push(bookmark);
  }

  await saveBookmarks();
  renderBookmarks();
  cancelForm();
}

// Edit bookmark
function editBookmark(id) {
  const bookmark = bookmarks.find(b => b.id === id);
  if (!bookmark) return;

  editingId = id;
  document.getElementById('titleInput').value = bookmark.title;
  document.getElementById('urlInput').value = bookmark.url;
  document.getElementById('categoryInput').value = bookmark.category;
  document.getElementById('descriptionInput').value = bookmark.description || '';
  document.getElementById('addForm').classList.add('show');
  document.getElementById('titleInput').focus();
}

// Delete bookmark
async function deleteBookmark(id) {
  if (!confirm('Are you sure you want to delete this bookmark?')) {
    return;
  }

  bookmarks = bookmarks.filter(b => b.id !== id);
  await saveBookmarks();
  renderBookmarks();
}

// Get first letter for icon
function getInitial(text) {
  return text.charAt(0).toUpperCase();
}

// Render bookmarks grouped by category
function renderBookmarks() {
  const bookmarksList = document.getElementById('bookmarksList');

  if (bookmarks.length === 0) {
    bookmarksList.innerHTML = `
            <div class="empty-state">
                <svg fill="currentColor" viewBox="0 0 20 20">
                    <path d="M5 4a2 2 0 012-2h6a2 2 0 012 2v14l-5-2.5L5 18V4z"></path>
                </svg>
                <p>No bookmarks yet. Add one above to get started!</p>
            </div>
        `;
    return;
  }

  // Group bookmarks by category
  const grouped = {};
  bookmarks.forEach(bookmark => {
    const cat = bookmark.category || 'Uncategorized';
    if (!grouped[cat]) {
      grouped[cat] = [];
    }
    grouped[cat].push(bookmark);
  });

  // Render categories
  bookmarksList.innerHTML = Object.keys(grouped).sort().map(category => `
        <div class="category">
            <div class="category-title">${escapeHtml(category)}</div>
            ${grouped[category].map(bookmark => `
                <div class="bookmark-item">
                    <div class="bookmark-icon">${getInitial(bookmark.title)}</div>
                    <div class="bookmark-content">
                        <div class="bookmark-title">
                            <a href="${escapeHtml(bookmark.url)}" target="_blank" rel="noopener noreferrer">
                                ${escapeHtml(bookmark.title)}
                            </a>
                        </div>
                        <div class="bookmark-url">${escapeHtml(bookmark.url)}</div>
                        ${bookmark.description ? `<div class="bookmark-description">${escapeHtml(bookmark.description)}</div>` : ''}
                    </div>
                    <div class="bookmark-actions">
                        <button class="edit-btn" onclick="editBookmark(${bookmark.id})">Edit</button>
                        <button class="delete-btn" onclick="deleteBookmark(${bookmark.id})">Delete</button>
                    </div>
                </div>
            `).join('')}
        </div>
    `).join('');
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Load bookmarks on startup
loadBookmarks();
