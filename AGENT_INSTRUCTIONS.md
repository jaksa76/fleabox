# Building Apps on Fleabox

Fleabox is a tiny self-hosted application hub. It serves static web apps and stores per-user data as JSON files on the filesystem.

## How It Works

- Apps are static HTML/CSS/JS files in `/srv/fleabox/<app-id>/`
- User data is stored in `~/.local/share/fleabox/<app-id>/data/`
- Authentication is automatic - when you visit an app, a token is set in your cookies
- All data operations use simple REST endpoints

## API Operations

### GET - Read Data

Read a JSON file:
```javascript
const response = await fetch(`/api/<app-id>/data/todos.json`);
if (response.ok) {
    const todos = await response.json();
} else if (response.status === 404) {
    // File doesn't exist yet
}
```

List directory contents:
```javascript
const response = await fetch(`/api/<app-id>/data/`);
const entries = await response.json();
// Returns: [{ name: "file.json", type: "file", size: 1234, mtime: 1234567890 }, ...]
```

### PUT - Write Data

Save a JSON file:
```javascript
await fetch(`/api/<app-id>/data/todos.json`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(todos)
});
```

Parent directories are created automatically. Maximum size: 10MB.

### DELETE - Remove Data

Delete a file:
```javascript
await fetch(`/api/<app-id>/data/todos.json`, {
    method: 'DELETE'
});
```

Delete a directory recursively:
```javascript
await fetch(`/api/<app-id>/data/archive?recursive=true`, {
    method: 'DELETE'
});
```

## Example App

Create `/srv/fleabox/todo/index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Todo - Fleabox</title>
</head>
<body>
    <input id="newTodo" type="text" />
    <button onclick="addTodo()">Add</button>
    <div id="list"></div>
    
    <script>
        const APP_ID = 'todo';
        let todos = [];
        
        async function loadTodos() {
            const response = await fetch(`/api/${APP_ID}/data/todos.json`);
            if (response.ok) {
                todos = await response.json();
            }
            render();
        }
        
        async function saveTodos() {
            await fetch(`/api/${APP_ID}/data/todos.json`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(todos)
            });
        }
        
        async function addTodo() {
            const input = document.getElementById('newTodo');
            todos.push({ text: input.value, done: false });
            input.value = '';
            await saveTodos();
            render();
        }
        
        function render() {
            const list = document.getElementById('list');
            list.innerHTML = todos.map((todo, i) => `
                <div>
                    <input type="checkbox" ${todo.done ? 'checked' : ''} 
                           onchange="toggleTodo(${i})">
                    ${todo.text}
                </div>
            `).join('');
        }
        
        async function toggleTodo(index) {
            todos[index].done = !todos[index].done;
            await saveTodos();
            render();
        }
        
        loadTodos();
    </script>
</body>
</html>
```

## Running Fleabox

Development mode (no authentication required):
```bash
fleabox --dev --apps-dir ./my-apps
```

Production mode (requires reverse proxy with `X-Remote-User` header):
```bash
fleabox
```

Apps are served at `http://localhost:3000/<app-id>/`
