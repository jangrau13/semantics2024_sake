DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
                                     id SERIAL PRIMARY KEY,
                                     email VARCHAR(255) NOT NULL UNIQUE,
                                     preferred_username VARCHAR(255),
                                     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                     last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
                                        id SERIAL PRIMARY KEY,
                                        user_id INT NOT NULL UNIQUE,
                                        preferred_username VARCHAR(255),
                                        session_id VARCHAR NOT NULL,
                                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                                        FOREIGN KEY (user_id) REFERENCES users(id)
);
