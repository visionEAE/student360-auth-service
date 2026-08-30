-- Demo identities (declared assumption 7: seed data, not migration). Every password is
-- "student360". external_reference values are the ids core-service and lms-service seed for the
-- same people, which is what makes the ref claim usable for fine-grained authorization.

INSERT INTO auth.role (name) VALUES ('STUDENT'), ('ADVISOR'), ('ADMIN');

INSERT INTO auth.app_user (id, email, password_hash, full_name, external_reference, active, created_at) VALUES
    ('11111111-1111-1111-1111-000000001001', 'ana.torres@u.icesi.edu.co',   '$2a$10$9ioK0g4OaVjF7UrQzGd8pOZneaLz4JIbfS4MIzXilFI0hAO3ANY0a', 'Ana Torres',   'S-1001', TRUE, now()),
    ('11111111-1111-1111-1111-000000001002', 'luis.gomez@u.icesi.edu.co',   '$2a$10$UldSRXkzVQbIADlguDzNS.ZTRxTtD/4LsnWlTf8bBJM7Cf1SFBXwm', 'Luis Gómez',   'S-1002', TRUE, now()),
    ('11111111-1111-1111-1111-000000001003', 'maria.rojas@u.icesi.edu.co',  '$2a$10$4B7cDfuQLlK8OguodILIl.hEKGhyjJtGLyT3Iw/1lZ3QxwOYcJrpu', 'María Rojas',  'S-1003', TRUE, now()),
    ('22222222-2222-2222-2222-000000002001', 'carlos.mejia@icesi.edu.co',   '$2a$10$rhH45TmRvB10/GZ3LSHlk.fjrANDmPcPnF4nFnfXFQPu1iLHKDDb6', 'Carlos Mejía', 'A-2001', TRUE, now()),
    ('22222222-2222-2222-2222-000000002002', 'diana.perez@icesi.edu.co',    '$2a$10$bK/xaWfk0MrvklMPwRLDQ.QMgNYusKNvlU3py2pMw6Zi5.MTsnZL.', 'Diana Pérez',  'A-2002', TRUE, now()),
    ('33333333-3333-3333-3333-000000003001', 'admin@icesi.edu.co',          '$2a$10$0RE9x2AUBKPuGODZl7hgTeJBGCHRewro0FCAoirsqEsRwK7p8Bj0O', 'Platform Admin', NULL,   TRUE, now());

INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'STUDENT' WHERE u.external_reference LIKE 'S-%';
INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'ADVISOR' WHERE u.external_reference LIKE 'A-%';
INSERT INTO auth.user_role (user_id, role_id)
SELECT u.id, r.id FROM auth.app_user u JOIN auth.role r ON r.name = 'ADMIN' WHERE u.email = 'admin@icesi.edu.co';
