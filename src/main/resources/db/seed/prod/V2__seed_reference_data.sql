-- Production seed: the same demo identities as dev, but no password travels in this file — the
-- values arrive as Flyway placeholders fed from Secret Manager (SEED_STUDENT_PASSWORD /
-- SEED_STAFF_PASSWORD), and pgcrypto hashes them at migration time. gen_salt('bf') produces
-- $2a$ hashes, which is exactly what BCryptPasswordEncoder verifies.

INSERT INTO auth.role (name) VALUES ('STUDENT'), ('ADVISOR'), ('ADMIN');

INSERT INTO auth.app_user (id, email, password_hash, full_name, external_reference, active, created_at) VALUES
    ('11111111-1111-1111-1111-000000001001', 'ana.torres@u.icesi.edu.co',  extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Ana Torres',   'S-1001', TRUE, now()),
    ('11111111-1111-1111-1111-000000001002', 'luis.gomez@u.icesi.edu.co',  extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Luis Gómez',   'S-1002', TRUE, now()),
    ('11111111-1111-1111-1111-000000001003', 'maria.rojas@u.icesi.edu.co', extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'María Rojas',  'S-1003', TRUE, now()),
    ('22222222-2222-2222-2222-000000002001', 'carlos.mejia@icesi.edu.co',  extensions.crypt('${seed_staff_password}',   extensions.gen_salt('bf', 10)), 'Carlos Mejía', 'A-2001', TRUE, now()),
    ('22222222-2222-2222-2222-000000002002', 'diana.perez@icesi.edu.co',   extensions.crypt('${seed_staff_password}',   extensions.gen_salt('bf', 10)), 'Diana Pérez',  'A-2002', TRUE, now()),
    ('33333333-3333-3333-3333-000000003001', 'admin@icesi.edu.co',         extensions.crypt('${seed_staff_password}',   extensions.gen_salt('bf', 10)), 'Platform Admin', NULL,   TRUE, now());

INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'STUDENT' WHERE u.external_reference LIKE 'S-%';
INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'ADVISOR' WHERE u.external_reference LIKE 'A-%';
INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'ADMIN' WHERE u.email = 'admin@icesi.edu.co';
