/**
[test]
reason = "Array element-level SELECT permissions (items[*]) must filter elements by identity. reduce_document / apply_select_field_permissions / filter_fields_by_permission expanded items[*] via Value::each (ascending indices) and cut each denied element with Value::cut, which does Vec::remove(i) -- shifting later indices down. Cutting forward therefore invalidated the pending indices: a deny-all leaked the odd-indexed elements ([1,3,5]) and a predicate kept/dropped the wrong elements. Fixed by cutting in reverse (descending) index order at every site."
issue = 7356

[[test.results]]
value = "'OK'"

[[test.results]]
value = "{ id: doc:1, items: [] }"

[[test.results]]
value = "{ id: docp:1, items: [{ n: 0 }, { n: 2 }, { n: 4 }] }"

[env]
imports = ["reproductions/7356_array_element_select_permission_leak_import.surql"]
auth = { namespace = "test", database = "test", access = "user", rid = "person:guest" }

*/

-- Authenticated as record user person:guest.
RETURN 'OK';

-- Deny-all element permission: the whole array must be empty (pre-fix it
-- leaked the odd-indexed elements [{n:1},{n:3},{n:5}]).
SELECT * FROM ONLY doc:1;

-- Per-element predicate: only the even-n elements survive, by identity
-- (pre-fix the index-shift kept {n:3},{n:5} and dropped {n:4}).
SELECT * FROM ONLY docp:1;
