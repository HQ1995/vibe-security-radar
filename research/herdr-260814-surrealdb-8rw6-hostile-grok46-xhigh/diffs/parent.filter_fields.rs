/// Filter fields from a value based on field-level permissions.
pub(crate) async fn filter_fields_by_permission(
	ctx: &ExecutionContext,
	state: &FieldState,
	value: &mut Value,
) -> Result<(), ControlFlow> {
	if state.field_permissions.is_empty() {
		return Ok(());
	}

	// Collect fields to check. `Strand::clone` is a 24-byte inline
	// copy for short names (the vast majority of field names) or an
	// `Arc` refcount bump for long ones -- either way zero heap
	// allocation per key, unlike `.to_string()` (blanket `Display`
	// impl allocates + formats) or `.as_str().to_owned()` (direct
	// `alloc + memcpy`). Probing through `.as_str()` works because
	// `HashMap<String, _>::get` accepts any `&Q` where
	// `String: Borrow<Q>`, and `Object::remove` already takes `&str`.
	let field_names: Vec<Strand> = {
		let Value::Object(obj) = &*value else {
			return Ok(());
		};
		obj.keys().cloned().collect()
	};

	for field_name in field_names {
		// Check if there's a permission for this field
		if let Some(perm) = state.field_permissions.get(field_name.as_str()) {
			let allowed = check_permission_for_value(perm, &*value, ctx)
				.await
				.context("Failed to check field permission")?;

			if !allowed && let Value::Object(obj) = value {
				obj.remove(field_name.as_str());
			}
		}
	}

	Ok(())
}
