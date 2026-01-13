# How to Make a Self-Hosted App

It turns out that building self-hosted web apps can be surprisingly simple. You don’t need complex backend frameworks, databases, or deployment pipelines because the user is implicitly trusted.

You only need a backend that can serve static files and store per-user data. Fleabox is a tiny Rust server that does exactly that. You don't need to write any server-side code, no need to set up a database, no need to set up user authentication other than your operating system user.

# Let's Build a TODO App

We’re going to create one file: `/srv/fleabox/todo/index.html`. Fleabox will serve it at `/todo`, and we’ll persist data via `GET`/`PUT` to `/api/todo/data/todos.json`.

### Doanload and install fleabox

```bash
sudo curl -L -o /usr/local/bin/fleabox https://github.com/jaksa76/fleabox/releases/download/v1.0/fleabox
sudo chmod +x /usr/local/bin/fleabox
```

If you don't have root access, you can also run fleabox from wherever you like.

### Create the App Directory
FFleabox serves static files from `/srv/fleabox/`. Let's create a directory for our app:

```bash
sudo mkdir -p /srv/fleabox/tutorial
```

Again, if you don't have root access, you can create the directory wherever you like, just remember to pass the `--apps-dir <your-app-directory>` argument when running fleabox.

### A Bare HTML Page

Create `/srv/fleabox/tutorial/index.html` with some minimal HTML:

```html
<html>
  <body>
    <div id="todoList">

    </div>
    <form onsubmit="createTodo(event)">
      <input id="new-todo" type="text" placeholder="What needs to be done?" />
      <button type="submit">Add Todo</button>
    </form>
  </body>
</html>
```

The createTodo function will be defined later.

### Adding a script

Add a `<script>` tag to the bottom of the body and let's define some initial state:

```html
...
    <script lang="javascript">
      let todoList = document.getElementById("todoList");
      let newTodoInput = document.getElementById("new-todo");
      let todos = [
        { text: "load washing machine", completed: false },
        { text: "do the dishes", completed: false }
      ];
    </script>
  </body>
```

### Rendering the TODO List

```javascript
    function render() {
      todoList.innerHTML = todos.map((todo, index) => `
          <div>
            <input type="checkbox" onchange="toggleTodo(${index})" ${todo.completed ? 'checked' : ''}/>
            ${todo.text}
          </div>
        `).join('');
    }

    // we will modify this later
    document.addEventListener("DOMContentLoaded", render);
```

For each todo item, we create a checkbox and display the text. The `toggleTodo` function will be defined later.

### Loading Existing TODOs from fleabox

Loading data from the server is as simple as fetching a JSON file. 

```javascript
    async function loadTodos() {
      const response = await fetch(`/api/tutorial/data/todos.json`);
      if (response.ok) {
        todos = await response.json();
      }
    }
```

If the file doesn't exist yet, we just ignore it.

### Saving TODOs to fleabox

The save function is also just a simple `PUT` request. No need for any server side logic. Fleabox will make sure that the data is saved in the right place for the authenticated user and that no one else can access it.

```javascript
    async function saveTodos() {
      await fetch(`/api/tutorial/data/todos.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(todos)
      });
    }
```

### Adding new TODOs

```javascript
    function createTodo(e) {
      e.preventDefault(); // we don't want to reload the page
      todos.push({ text: newTodoInput.value, completed: false });
      newTodoInput.value = ''; // reset input field
      saveTodos();
      render();
    }
```

### Toggling TODO Completion

```javascript
    function toggleTodo(index) {
      todos[index].completed = !todos[index].completed;
      saveTodos();
      render();
    }
```

### Load existing TODOs on page load

Finally let's replace the initial render call from Step 3 with loading existing todos first:

```javascript
    document.addEventListener("DOMContentLoaded", async () => {
      await loadTodos();
      render();
    });
```

### Run Fleabox

For now we will run fleabox in dev mode so that we can skip authentication:

```bash
fleabox --dev # optionally add --apps-dir <your-app-directory> if you created the app directory somewhere else
```

Now you can open http://localhost:3000/

You should see a list of all the installed apps. Click on "tutorial" to open your TODO app. Since we are running in dev mode, fleabox will skip authentication and use the user that is currently logged in on your machine.

### Exposing fleabox to the Internet

If you want to expose fleabox to the internet, you need to set up a reverse proxy with authentication and TLS termination. This is crucial for security, especially if you plan to access your apps remotely. Popular choices for reverse proxies include Nginx, Caddy and Traefik.

## What's Next?

In a similar way you can develop complex apps with your favorite frontend framework (React, Svelte, Vue, etc) and just use fleabox as a simple backend to serve the app and store user data.

Fleabox serves static files from `/srv/fleabox/<app-name>/` at the URL path `/<app-name>/`. User data is stored in `/var/lib/fleabox/<username>/<app-name>/data/`. Since fleabox is designed for self-hosted use, it assumes that the user accessing the machine is trusted.

Fleabox is ideal for simple self-hosted applications where each user manages their own data. However, it may not be suitable for applications that require:

- sharing data among multiple users
- logic that must sit on the server
- scheduled tasks (e.g., cron jobs)
- real-time communication (e.g., WebSockets)

for everything else, fleabox is a simple and incredibly effective solution.
