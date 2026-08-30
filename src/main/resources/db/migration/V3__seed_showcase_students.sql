-- Login accounts for the four showcase advisees (docs/api-contract-v2.md), so their own wellbeing
-- entries can be submitted through the real API rather than inserted directly. Same password
-- ("student360") and therefore the same bcrypt hash as every other seeded account — bcrypt
-- verification only depends on the password, not on which row the hash lives in.

INSERT INTO auth.app_user (id, email, password_hash, full_name, external_reference, active, created_at) VALUES
    ('11111111-1111-1111-1111-000000001007', 'juan.gomez@u.icesi.edu.co',     '$2a$10$9ioK0g4OaVjF7UrQzGd8pOZneaLz4JIbfS4MIzXilFI0hAO3ANY0a', 'Juan Pablo Gómez',    'S-1007', TRUE, now()),
    ('11111111-1111-1111-1111-000000001008', 'santiago.molina@u.icesi.edu.co', '$2a$10$9ioK0g4OaVjF7UrQzGd8pOZneaLz4JIbfS4MIzXilFI0hAO3ANY0a', 'Santiago Molina',     'S-1008', TRUE, now()),
    ('11111111-1111-1111-1111-000000001009', 'isabella.zapata@u.icesi.edu.co', '$2a$10$9ioK0g4OaVjF7UrQzGd8pOZneaLz4JIbfS4MIzXilFI0hAO3ANY0a', 'Isabella Zapata',     'S-1009', TRUE, now()),
    ('11111111-1111-1111-1111-000000001010', 'andres.ruiz@u.icesi.edu.co',     '$2a$10$9ioK0g4OaVjF7UrQzGd8pOZneaLz4JIbfS4MIzXilFI0hAO3ANY0a', 'Andrés Felipe Ruiz',  'S-1010', TRUE, now());

INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'STUDENT'
WHERE u.external_reference IN ('S-1007', 'S-1008', 'S-1009', 'S-1010');
