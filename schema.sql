-- sqlite
CREATE TABLE envs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    public BOOLEAN DEFAULT FALSE
);
CREATE INDEX author_index ON envs (author);

CREATE TABLE visibleTo (
    envs_id INTEGER NOT NULL,
    gh_username TEXT NOT NULL,
    PRIMARY KEY (envs_id, gh_username)
    FOREIGN KEY (envs_id) REFERENCES envs(id)
);
