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
				// SECURITY: iterate in reverse. `each` yields ascending
				// array indices and `Value::cut` removes via `Vec::remove`
				// (shifting later indices down), so a forward pass would
				// let each removal invalidate the pending indices and leak
				// the odd-indexed elements (issue #7356). Removing higher
				// indices first keeps the pending lower indices valid.
				for path in original.each(&idiom.0).into_iter().rev() {
					value.cut(&path.0);
				}
			}
			PhysicalPermission::Conditional(_) => {
				let original = snapshot.get_or_insert_with(|| value.clone());
				// SECURITY: iterate in reverse (see the Deny arm above and
				// issue #7356). Predicates read from `original` (immutable),
				// so evaluation order is irrelevant.
				for path in original.each(&idiom.0).into_iter().rev() {
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
