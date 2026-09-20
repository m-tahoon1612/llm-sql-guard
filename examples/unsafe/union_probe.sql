SELECT name, price FROM products WHERE id = 1
UNION SELECT NULL, NULL, table_name FROM information_schema.tables
