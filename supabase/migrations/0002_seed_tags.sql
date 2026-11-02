-- Default specialization tags. Previously seeded at process start, which never runs on Vercel.
INSERT INTO tags (id, name)
SELECT gen_random_uuid(), v.name
FROM (VALUES ('Real Estate'), ('Crypto'), ('Construction'), ('Business Owner'), ('International/Latin America')) AS v(name)
WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE lower(t.name) = lower(v.name));
