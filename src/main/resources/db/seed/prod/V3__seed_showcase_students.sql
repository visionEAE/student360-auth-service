-- Production counterpart of the dev showcase accounts; same placeholder-fed hashing as V2.

INSERT INTO auth.app_user (id, email, password_hash, full_name, external_reference, active, created_at) VALUES
    ('11111111-1111-1111-1111-000000001007', 'juan.gomez@u.icesi.edu.co',      extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Juan Pablo Gómez',   'S-1007', TRUE, now()),
    ('11111111-1111-1111-1111-000000001008', 'santiago.molina@u.icesi.edu.co', extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Santiago Molina',    'S-1008', TRUE, now()),
    ('11111111-1111-1111-1111-000000001009', 'isabella.zapata@u.icesi.edu.co', extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Isabella Zapata',    'S-1009', TRUE, now()),
    ('11111111-1111-1111-1111-000000001010', 'andres.ruiz@u.icesi.edu.co',     extensions.crypt('${seed_student_password}', extensions.gen_salt('bf', 10)), 'Andrés Felipe Ruiz', 'S-1010', TRUE, now());

INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'STUDENT'
WHERE u.external_reference IN ('S-1007', 'S-1008', 'S-1009', 'S-1010');
