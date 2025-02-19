CREATE DATABASE flask_crud;

USE flask_crud;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) NOT NULL,
    dob DATE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user'
);

-- Insert Admin Account (Change email/password as needed)
INSERT INTO users (name, email, phone, dob, password, role) 
VALUES ('Admin', 'admin@example.com', '1234567890', '2000-01-01', 
        '$2b$12$Y7g8mtmPZyNn/Lx.4NwXq.3Pbnr2wn7ob1MJ5GRQ0i8GIMq2qkoxC', 'admin');
