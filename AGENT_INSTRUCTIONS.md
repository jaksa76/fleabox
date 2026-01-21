# Agent Instructions: Building Apps on Fleabox

This document provides comprehensive instructions for AI agents building web applications on the Fleabox platform.

## What is Fleabox?

Fleabox is a tiny, self-hosted application hub built in Rust. It serves multiple static web apps over HTTP with per-user, per-app data storage on the filesystem. There's no database, no plugin system, and no server-side app code needed.

**Key Design Principles:**
- Personal web apps should be boring, inspectable, and easy to back up
- Each user's data is isolated in their own directory
- Apps are single-page applications (SPAs) with static HTML/CSS/JavaScript
- All backend functionality is provided by Fleabox's simple REST API

## Directory Structure

### App Location
Apps are served from `/srv/fleabox/<app-id>/` (or a custom directory specified with `--apps-dir`)

**Example:**
```
/srv/fleabox/
├── todo/
│   └── index.html
├── notes/
│   └── index.html
└── bookmarks/
    └── index.html
```

### Data Storage
User data is stored in: `~/.local/share/fleabox/<app-id>/data/`

Each user has their own isolated data directory based on their system username.

## Fleabox API

Fleabox provides a simple REST API for data operations:

### Authentication
In development mode (`--dev`), Fleabox uses the current system user and doesn't require authentication headers.

In production mode, authentication is handled by a reverse proxy that sets the `X-Remote-User` HTTP header.

Apps use a token-based authentication system:
1. Obtain a token via `/api/token` endpoint
2. Store the token in a cookie named `fleabox_token`
3. All subsequent API calls use this cookie for authentication

### API Endpoints

#### Get Token
```
GET /api/token?app=<app-id>
```
Returns a token that's valid for 1 hour. The token is automatically set as a cookie.

#### Read Data
```
GET /api/<app-id>/data/<path>
```
- Returns file content with appropriate MIME type for files
- Returns JSON array of directory entries for directories
- Returns 404 if path doesn't exist

**Directory listing format:**
```json
[
  {
    "name": "file.json",
    "type": "file",
    "size": 1234,
    "mtime": 1234567890
  },
  {
    "name": "subfolder",
    "type": "dir",
    "mtime": 1234567890
  }
]
```

#### Write Data
```
PUT /api/<app-id>/data/<path>
Content-Type: application/json

<JSON data>
```
- Creates or overwrites file at specified path
- Automatically creates parent directories if needed
- Performs atomic writes using temporary files
- Maximum request size: 10MB
- Returns 200 on success

#### Delete Data
```
DELETE /api/<app-id>/data/<path>
```
- Deletes file or empty directory
- For directories: must be empty or use `?recursive=true`
- Returns 200 on success
- Returns 404 if path doesn't exist

## Building an App: Step-by-Step Guide

### 1. Choose an App ID
Pick a short, descriptive identifier using only lowercase letters, numbers, and hyphens.

**Examples:** `todo`, `notes`, `journal`, `bookmarks`

### 2. Create the App Directory
```bash
mkdir -p /srv/fleabox/<app-id>
```

Or use a custom directory:
```bash
mkdir -p ./my-apps/<app-id>
```

### 3. Create index.html

Your app should be a single HTML file (or include additional assets in the same directory).

**Minimal template:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My App - Fleabox</title>
    <style>
        /* Your styles here */
    </style>
</head>
<body>
    <div id="app">
        <!-- Your app UI here -->
    </div>
    
    <script>
        const APP_ID = '<app-id>'; // Your app ID
        
        // Your app logic here
    </script>
</body>
</html>
```

### 4. Implement Data Operations

#### Token Management
Before making any API calls, obtain a token:

```javascript
async function initializeAuth() {
    try {
        // Get token and set cookie
        const response = await fetch(`/api/token?app=${APP_ID}`);
        if (!response.ok) {
            throw new Error('Failed to get authentication token');
        }
        // Token is automatically set as a cookie
        return true;
    } catch (error) {
        console.error('Authentication failed:', error);
        return false;
    }
}

// Call this before making any other API requests
initializeAuth().then(success => {
    if (success) {
        loadData();
    }
});
```

#### Loading Data
```javascript
async function loadData() {
    try {
        const response = await fetch(`/api/${APP_ID}/data/mydata.json`);
        if (response.ok) {
            const data = await response.json();
            // Use the data
            return data;
        } else if (response.status === 404) {
            // File doesn't exist yet, return default
            return [];
        } else {
            throw new Error('Failed to load data');
        }
    } catch (error) {
        console.error('Error loading data:', error);
        return [];
    }
}
```

#### Saving Data
```javascript
async function saveData(data) {
    try {
        const response = await fetch(`/api/${APP_ID}/data/mydata.json`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error('Failed to save data');
        }
    } catch (error) {
        console.error('Error saving data:', error);
    }
}
```

#### Deleting Data
```javascript
async function deleteFile(filename) {
    try {
        const response = await fetch(`/api/${APP_ID}/data/${filename}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            throw new Error('Failed to delete file');
        }
    } catch (error) {
        console.error('Error deleting file:', error);
    }
}
```

#### Working with Directories
```javascript
async function listFiles() {
    try {
        const response = await fetch(`/api/${APP_ID}/data/`);
        if (response.ok) {
            const entries = await response.json();
            return entries;
        } else if (response.status === 404) {
            return [];
        }
    } catch (error) {
        console.error('Error listing files:', error);
        return [];
    }
}
```

### 5. Error Handling

Always handle potential errors from the API:

```javascript
async function apiCall() {
    try {
        const response = await fetch(url, options);
        
        if (!response.ok) {
            const error = await response.json();
            console.error('API Error:', error);
            // Show user-friendly error message
            showError(error.message || 'An error occurred');
            return null;
        }
        
        return await response.json();
    } catch (error) {
        console.error('Network Error:', error);
        showError('Network error. Please check your connection.');
        return null;
    }
}
```

### 6. Security Best Practices

#### Prevent XSS Attacks
Always escape user-generated content:

```javascript
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// When rendering:
element.innerHTML = escapeHtml(userInput);
```

#### Path Validation
- Never construct file paths from user input without validation
- Use simple, flat file structures or validated subdirectories
- Avoid special characters in filenames

#### Data Validation
- Validate all user input before saving
- Set reasonable size limits for data
- Use JSON.parse/stringify for structured data

## Example Apps

### Simple TODO App

```javascript
const APP_ID = 'todo';
let todos = [];

async function init() {
    if (!await initializeAuth()) return;
    await loadTodos();
    render();
}

async function loadTodos() {
    const response = await fetch(`/api/${APP_ID}/data/todos.json`);
    if (response.ok) {
        todos = await response.json();
    }
}

async function saveTodos() {
    await fetch(`/api/${APP_ID}/data/todos.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(todos)
    });
}

async function addTodo(text) {
    todos.push({
        id: Date.now(),
        text: text,
        completed: false,
        createdAt: new Date().toISOString()
    });
    await saveTodos();
    render();
}

async function toggleTodo(id) {
    const todo = todos.find(t => t.id === id);
    if (todo) {
        todo.completed = !todo.completed;
        await saveTodos();
        render();
    }
}

function render() {
    // Update DOM with current todos
}

// Initialize on page load
init();
```

## Running Fleabox

### Development Mode
```bash
fleabox --dev
```
- Skips authentication (uses current system user)
- Serves apps at `http://localhost:3000/<app-id>`
- Shows app listing at `http://localhost:3000/`

### Development with Custom Directory
```bash
fleabox --dev --apps-dir ./examples
```

### Production Mode
```bash
fleabox
```
Requires a reverse proxy with authentication (e.g., Nginx, Caddy, Traefik) that sets the `X-Remote-User` header.

## Testing Your App

1. Start Fleabox in dev mode:
   ```bash
   fleabox --dev --apps-dir ./my-apps
   ```

2. Open `http://localhost:3000/` to see the app listing

3. Click on your app or navigate to `http://localhost:3000/<app-id>/`

4. Test all functionality:
   - Create data
   - Read data (refresh page)
   - Update data
   - Delete data

5. Check data storage:
   ```bash
   ls -la ~/.local/share/fleabox/<app-id>/data/
   ```

## Common Patterns

### Auto-save on Change
```javascript
let saveTimeout;

function autoSave() {
    clearTimeout(saveTimeout);
    saveTimeout = setTimeout(() => {
        saveData(currentData);
    }, 1000); // Save 1 second after last change
}
```

### Loading States
```javascript
let isLoading = false;

async function loadWithStatus() {
    isLoading = true;
    renderLoadingState();
    
    try {
        const data = await loadData();
        return data;
    } finally {
        isLoading = false;
        render();
    }
}
```

### Multiple Data Files
```javascript
// Organize data in separate files
await saveData('settings.json', settings);
await saveData('items.json', items);
await saveData('archive/old-items.json', oldItems);
```

## Limitations

Fleabox is designed for simple, self-hosted personal apps. It's **not suitable** for:

- **Multi-user collaboration**: Data is isolated per user
- **Server-side logic**: All logic runs in the browser
- **Scheduled tasks**: No cron or background jobs
- **Real-time communication**: No WebSocket support
- **Large files**: 10MB limit per request
- **Complex queries**: No database or search functionality

## Best Practices

1. **Keep it simple**: Embrace the constraints. Complex features may indicate Fleabox isn't the right tool.

2. **Store data as JSON**: Use simple JSON files for structured data.

3. **Use meaningful filenames**: Make data files easy to inspect and back up.

4. **Handle offline gracefully**: Cache data in memory and show appropriate error messages.

5. **Provide export functionality**: Let users download their data as JSON or CSV.

6. **Progressive enhancement**: Start with basic functionality, then add features incrementally.

7. **Test with real data**: Use the app yourself to ensure it handles edge cases.

8. **Document your data format**: Include comments or a README explaining the data structure.

## Framework Integration

While Fleabox works great with vanilla JavaScript, you can use modern frameworks:

### With Build Tools
1. Build your app: `npm run build`
2. Copy `dist/` contents to `/srv/fleabox/<app-id>/`
3. Ensure the built app uses relative paths

### Without Build Tools
Include frameworks via CDN:

```html
<!-- React -->
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

<!-- Vue -->
<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>

<!-- Alpine.js -->
<script defer src="https://unpkg.com/alpinejs@3/dist/cdn.min.js"></script>
```

## Troubleshooting

### "Failed to load data"
- Check that Fleabox is running
- Verify the app ID matches exactly
- Check browser console for specific error messages
- Ensure token was obtained successfully

### "Unauthorized" errors
- In dev mode: Verify `--dev` flag is set
- In production: Check reverse proxy authentication configuration
- Verify the `X-Remote-User` header is being set correctly

### Data not persisting
- Check file permissions on data directory
- Verify no errors in browser console during save
- Check Fleabox server logs for errors
- Ensure data doesn't exceed 10MB limit

### App not loading
- Verify app directory exists at correct path
- Check that `index.html` exists
- Verify Fleabox is running and accessible
- Check browser console for JavaScript errors

## Additional Resources

- **Example Apps**: See the `/examples` directory in the Fleabox repository
  - `todo`: Simple task list
  - `notes`: Note-taking app with search
  - `bookmarks`: Link organization
  - `journal`: Daily journaling
  - `habits`: Habit tracking

- **Repository**: https://github.com/jaksa76/fleabox
- **Fleabox API**: All endpoints follow the pattern `/api/<app-id>/data/<path>`

## Quick Reference

### Essential API Patterns

```javascript
// Get token first
await fetch(`/api/token?app=${APP_ID}`);

// Load data
const response = await fetch(`/api/${APP_ID}/data/file.json`);
const data = response.ok ? await response.json() : defaultData;

// Save data
await fetch(`/api/${APP_ID}/data/file.json`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
});

// Delete data
await fetch(`/api/${APP_ID}/data/file.json`, { method: 'DELETE' });

// List directory
const response = await fetch(`/api/${APP_ID}/data/`);
const entries = await response.json();
```

### File Structure

```
/srv/fleabox/<app-id>/
└── index.html          (Required: Your app's entry point)

~/.local/share/fleabox/<app-id>/data/
├── file1.json          (Your app's data files)
├── file2.json
└── subdirectory/
    └── more-data.json
```

---

**Remember**: Fleabox is designed for simplicity. If you find yourself fighting against its constraints, consider whether it's the right tool for your use case. For simple personal productivity apps with per-user data storage, it's perfect!
