# Family Site — Local Backend

This adds a minimal Node.js + SQLite backend to store applications submitted from the site.

Quick start (Windows):

1. Open a terminal in the project folder.
2. Install dependencies:

```bash
npm install
```

3. Run the server:

```bash
npm start
```

4. Open the site in your browser:

http://localhost:3000

Notes:
- The server creates a `data/apps.db` SQLite file and provides API endpoints under `/api/*`.
- The front-end will try the API first and fall back to the existing localStorage behaviour if the server is unavailable.
