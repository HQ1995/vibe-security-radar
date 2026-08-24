/// Filter fields from a value based on field-level permissions.
///
/// Each `(idiom, perm)` entry is expanded via [`Value::each`] to handle
/// wildcards (`outer.*`, `items[*]`), then each concrete path is checked
/// with `$value` bound to the picked field value -- matching the legacy
/// [`crate::doc::pluck::Document::pluck_select`] semantics that the
/// streaming runtime previously skipped for nested paths (issue #83).
pub(crate) async fn filter_fields_by_permission(
	ctx: &ExecutionContext,
	state: &FieldState,
	value: &mut Value,
) -> Result<(), ControlFlow> {
	if state.field_permissions.is_empty() {
		return Ok(());
	}
	if !matches!(value, Value::Object(_)) {
		return Ok(());
	}

	// Snapshot the row only when we actually need to evaluate something
	// against the unmutated document. Per-field denies cut from `value`;
	// predicates and `each` read from the snapshot so earlier cuts don't
	// affect later field expansion.
	let mut snapshot: Option<Value> = None;
	for (idiom, perm) in state.field_permissions.iter() {
		match perm {
			PhysicalPermission::Allow => continue,
			PhysicalPermission::Deny => {
				let original = snapshot.get_or_insert_with(|| value.clone());
				for path in original.each(&idiom.0) {
					value.cut(&path.0);
				}
			}
			PhysicalPermission::Conditional(_) => {
				let original = snapshot.get_or_insert_with(|| value.clone());
				for path in original.each(&idiom.0) {
					let field_value = original.pick(&path.0);
					let allowed =
						check_permission_for_value(perm, original, Some(&field_value), ctx)
							.await
							.map_err(|e| {
							ControlFlow::Err(anyhow::anyhow!(
								"Failed to check field permission: {e}"
							))
						})?;
					if !allowed {
						value.cut(&path.0);
					}
				}
			}
		}
	}

	Ok(())
}
