CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT INTO items VALUES(1, 'apple', 1.50);
INSERT INTO items VALUES(2, 'banana', 0.75);
SELECT name, price FROM items WHERE price > 1.0 ORDER BY price DESC;
